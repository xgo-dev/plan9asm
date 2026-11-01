package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Complete legacy/VEX packed estimate formats, independently of production.
// Scalar SS estimates and the EVEX 14/28 families have separate owners.
var x86PackedReciprocalReadCases = []struct {
	op, bank string
	width    int
	legacy   bool
}{
	{"RCPPS", "X", 16, true}, {"RSQRTPS", "X", 16, true},
	{"VRCPPS", "X", 16, false}, {"VRCPPS", "Y", 32, false},
	{"VRSQRTPS", "X", 16, false}, {"VRSQRTPS", "Y", 32, false},
}

func TestX86PackedReciprocalBytesAndNativePermissionBoundary(t *testing.T) {
	for _, row := range x86PackedReciprocalReadCases {
		t.Run(row.op+row.bank, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.op+" "+row.bank+"0,"+row.bank+"2")
			mask := x86CallerVectorByteMask(int64(row.width))
			for missing := -1; missing < row.width; missing++ {
				initial := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				initial.writeVector(0, row.width, mask, true)
				initial.writeVector(2, 64, 0x55aa00ff00ff55aa, true)
				initial.pointerGP[7], initial.masks[1] = true, true
				if missing >= 0 {
					initial.writeVector(0, row.width, mask&^(1<<uint(missing)), true)
				}
				state, want := initial.clone(), initial.clone()
				defined := mask
				if missing >= 0 {
					defined = 0
				}
				want.writeVector(2, row.width, defined, row.legacy)
				if accepted, known := x86ResultPackedReciprocalStep(ins, &state, nil, "amd64", false); !accepted || !known || !reflect.DeepEqual(state, want) {
					t.Fatal("packed estimate invented input bytes or changed unrelated state", missing, state, want)
				}
			}
			ins.Args[0] = x86ScalarLaneInstruction(t, row.op+" (AX),"+row.bank+"2").Args[0]
			initial := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
			initial.pointerGP[0] = true
			for _, native := range []bool{false, true} {
				state := initial.clone()
				accepted, known := x86ResultPackedReciprocalStep(ins, &state, nil, "amd64", native)
				if !known || accepted != native {
					t.Fatal("strict proof acquired native storage or paired native read lost its address", native, accepted, known)
				}
				want := initial.clone()
				if native {
					want.writeVector(2, row.width, mask, row.legacy)
				}
				if !reflect.DeepEqual(state, want) {
					t.Fatal("native continuation supplied unrelated permissions", state, want)
				}
			}
			for _, mutate := range []func(*Instr, *x86ResultState){
				func(_ *Instr, s *x86ResultState) { s.pointerGP[0] = false },
				func(i *Instr, _ *x86ResultState) { i.x86Encoded = true },
				func(i *Instr, _ *x86ResultState) { i.x86AddressBits = 32 },
				func(i *Instr, _ *x86ResultState) { i.x86UnboundAddressOverride = true },
			} {
				changed, state := ins, initial.clone()
				mutate(&changed, &state)
				before := state.clone()
				if accepted, _ := x86ResultPackedReciprocalStep(changed, &state, nil, "amd64", true); accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("native estimate granted a missing pointer, raw entry or address binding")
				}
			}
		})
	}
}

func TestX86PackedReciprocalRegisterEstimatesRemainPureAndCSE(t *testing.T) {
	for _, row := range x86PackedReciprocalReadCases {
		t.Run(row.op+row.bank, func(t *testing.T) {
			source := "TEXT ·Estimate(SB),4,$0-16\nMOVQ out+0(FP),DI\nMOVQ input+8(FP),AX\n" +
				fmt.Sprintf("VMOVUPS (AX),%s0\n%s %s0,%s1\n%s %s0,%s2\n", row.bank, row.op, row.bank, row.bank, row.op, row.bank, row.bank)
			store := "VMOVUPS"
			if row.legacy {
				store = "MOVUPS"
			}
			source += fmt.Sprintf("%s %s1,(DI)\n%s %s2,32(DI)\nRET\n", store, row.bank, store, row.bank)
			ir, err := x86ScalarFPBitViewAPI(t, source, "func Estimate(out *[64]byte,input *[32]byte)\n", "amd64", "x86_64-unknown-linux-gnu", "Go")
			if err != nil {
				t.Fatal(err)
			}
			intrinsic := "@llvm.x86.sse.rcp.ps("
			if strings.Contains(row.op, "RSQRT") {
				intrinsic = "@llvm.x86.sse.rsqrt.ps("
			}
			if row.width == 32 {
				intrinsic = strings.Replace(intrinsic, ".sse.", ".avx.", 1)
				intrinsic = strings.Replace(intrinsic, ".ps(", ".ps.256(", 1)
			}
			before := x86StringMemoryFunction(t, ir, "Estimate")
			after := x86StringMemoryFunction(t, x86DwordProductIROptimize(t, ir), "Estimate")
			if strings.Count(before, intrinsic) != 2 || strings.Count(after, intrinsic) != 1 || strings.Contains(before, "asm sideeffect \""+strings.ToLower(row.op)) {
				t.Fatal("pure register estimate lost its original intrinsic or legal CSE", before, after)
			}
		})
	}
}

func TestX86PackedReciprocalPublicInstructionCaseNormalization(t *testing.T) {
	for _, row := range x86PackedReciprocalReadCases {
		for _, memory := range []bool{false, true} {
			for _, name := range []string{row.op, strings.ToLower(row.op), strings.ToLower(row.op[:2]) + row.op[2:]} {
				t.Run(fmt.Sprint(name, row.bank, "/memory=", memory), func(t *testing.T) {
					operand := row.bank + "0"
					if memory {
						operand = "(AX)"
					}
					source := fmt.Sprintf("TEXT Estimate(SB),4,$0-8\nMOVQ p+0(FP),AX\n%s %s,%s2\nRET\n", row.op, operand, row.bank)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					for index := range file.Funcs[0].Instrs {
						if file.Funcs[0].Instrs[index].Op == Op(row.op) {
							file.Funcs[0].Instrs[index].Op = Op(name)
						}
					}
					pkg := mustGoPackage(t, "normalization", "package normalization\nfunc Estimate(p *[32]byte)\n")
					resolve := func(symbol string) string { return symbol }
					signatures, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: signatures})
					if err != nil {
						t.Fatal("public lowercase instruction lost its original class", err)
					}
					body := x86StringMemoryFunction(t, ir, "Estimate")
					if memory {
						if !strings.Contains(body, `asm sideeffect "`+strings.ToLower(row.op)+` `) {
							t.Fatal("case normalization changed native opcode", body)
						}
					} else if strings.Contains(row.op, "RSQRT") != strings.Contains(body, ".rsqrt.ps") {
						t.Fatal("case normalization changed reciprocal versus reciprocal-square-root", body)
					}
				})
			}
		}
	}
}

func TestX86PackedReciprocalNativeFaultOwnerRetainsRequiredExecution(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "x86_packed_reciprocal_native_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]int{
		"x87IA32RequireNativeHost": 2, "x86FloatCompareExecutionTools": 1, "execution.requireAVX": 1,
		"goAssemblerOracleOutput": 1, "x86OrderingHintGoBytes": 1, "x86ScalarFPBitViewAPI": 1,
		"x86DwordProductIROptimize": 1, "execution.compileLLVM": 2, "x86ObserveMemoryFault": 2,
	}
	if err := x86CheckHalfIndirectCommandOwner(file, "TestCrossLinuxRuntimeMatrixX86PackedReciprocalNativeMemoryFaults", required); err != nil {
		t.Fatal(err)
	}
}

func TestX86PackedReciprocalMode32FrontendAddressNeedsPhysicalBinding(t *testing.T) {
	for _, row := range x86PackedReciprocalReadCases {
		if row.legacy {
			continue
		}
		for _, address := range []string{"16(R9)", "4294967295(R9)"} {
			t.Run(row.op+row.bank+address, func(t *testing.T) {
				instruction := row.op + " " + address + "," + row.bank + "2"
				goAssemblerOracleOutput(t, "386", "TEXT format(SB),4,$0-0\n"+instruction+"\nRET\n", "", true)
				ins := x86ScalarLaneInstruction(t, instruction)
				if _, known, err := x86PackedReciprocalProperties(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("Go's accepted mode32 frontend address acquired a physical binding or was mistaken for invalid grammar", known, err)
				}
			})
		}
	}
}

func TestX86PackedReciprocalNativeReadsPhysicalTargetsAndBackendBoundary(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			source, declaration := x86PackedReciprocalDeadSource()
			if target.arch == "386" {
				source = strings.ReplaceAll(strings.ReplaceAll(source, "MOVQ ", "MOVL "), "$0-8", "$0-4")
			}
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
				if err != nil {
					t.Fatal("physical estimate memory source rejected", api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "packed-native.ll", "packed-native.o", ir)
			}
		})
	}
	source, declaration := x86PackedReciprocalDeadSource()
	for _, target := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", target, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("native packed estimate crossed its backend boundary", target, api, err)
			}
		}
	}
}

func TestX86PackedReciprocalTypedInputsAndInitializedPublicSources(t *testing.T) {
	for _, row := range x86PackedReciprocalReadCases {
		for _, memory := range []bool{false, true} {
			first, preload := row.bank+"0", fmt.Sprintf("VMOVUPS (AX),%s0\n", row.bank)
			if memory {
				first, preload = "(AX)", ""
			}
			instruction := row.op + " " + first + "," + row.bank + "2"
			t.Run(instruction, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, instruction)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
				upper := x86TypedVectorUpperZero
				if row.legacy {
					upper = x86TypedVectorUpperPreserve
				}
				if !known || err != nil || !effect.requiresResultProof || len(effect.operands) != 2 ||
					effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 || effect.vector.upperWrite != upper {
					t.Error("packed estimate has no complete typed input/write/alias owner", known, err, effect)
				} else if source, destination := effect.operands[0], effect.operands[1]; source.index != 0 || !source.read || source.write || source.width != int64(row.width) ||
					destination.index != 1 || destination.read || !destination.write || destination.width != int64(row.width) ||
					memory && row.legacy && effect.vector.memoryAlignment != 16 {
					t.Error("packed estimate confused full input, written bytes or legacy native alignment", effect)
				}
				// No target-input preload in the memory case: the operation owns
				// that read. The old Y value separately exposes legacy upper bytes.
				source := "TEXT ·Value(SB),4,$0-24\nMOVQ out+0(FP),DI\nMOVQ input+8(FP),AX\nMOVQ old+16(FP),BX\n" +
					"VMOVUPS (BX),Y2\n" + preload + instruction + "\nVMOVUPS Y2,(DI)\nRET\n"
				declaration := "func Value(out,input,old *[32]byte)\n"
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				missing := preload
				if memory {
					missing = "MOVQ input+8(FP),AX\n"
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
							t.Fatal("initialized packed estimate source rejected", err)
						}
						negative := strings.Replace(source, missing, "", 1)
						if negative == source {
							t.Fatal("missing-input control lost its actual source")
						}
						if ir, err := x86ScalarFPBitViewAPI(t, negative, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("packed estimate supplied an observed numerical source or native address", err)
						}
					})
				}
			})
		}
	}
}

func x86PackedReciprocalDeadSource() (string, string) {
	var source, declarations strings.Builder
	for index, row := range x86PackedReciprocalReadCases {
		fmt.Fprintf(&source, "TEXT ·PackedEstimate%d(SB),4,$0-8\nMOVQ input+0(FP),AX\n%s (AX),%s2\nRET\n", index, row.op, row.bank)
		fmt.Fprintf(&declarations, "func PackedEstimate%d(input *[32]byte)\n", index)
	}
	return source.String(), declarations.String()
}

func TestX86PackedReciprocalDeadNativeReadsActualOptimizedObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required")
	}
	source, declaration := x86PackedReciprocalDeadSource()
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
		if err != nil {
			t.Fatal("initialized incoming native pointer rejected", api, err)
		}
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/IR_O2=%t", api, optimized), func(t *testing.T) {
				text, level := ir, "-O0"
				if optimized {
					text, level = x86DwordProductIROptimize(t, ir), "-O2"
				}
				for index, row := range x86PackedReciprocalReadCases {
					body := x86StringMemoryFunction(t, text, fmt.Sprint("PackedEstimate", index))
					t.Logf("actual %s/%d IR body:\n%s", row.op, row.width, body)
					volatile := strings.Contains(body, fmt.Sprintf("load volatile <%d x i8>", row.width))
					native := strings.Contains(body, fmt.Sprintf("call <%d x float> asm sideeffect", row.width/4)) &&
						strings.Contains(body, fmt.Sprintf("elementtype([%d x i8])", row.width)) &&
						strings.Contains(body, "*m") && strings.Contains(body, strings.ToLower(row.op))
					if !volatile && !native {
						t.Errorf("dead packed estimate lost its observable full-width native source: %s/%d\n%s", row.op, row.width, body)
					}
				}
				directory := t.TempDir()
				input, object := filepath.Join(directory, "dead.ll"), filepath.Join(directory, "dead.o")
				if err := os.WriteFile(input, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", input, "-o", object))
				listing := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "--disassemble", object))
				objectBytes, err := os.ReadFile(object)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("actual LLVM22 %s object SHA256=%x IR SHA256=%x\n%s", level, sha256.Sum256(objectBytes), sha256.Sum256([]byte(text)), listing)
				sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <(PackedEstimate[0-9]+)>:\n`).FindAllSubmatchIndex(listing, -1)
				if len(sections) != len(x86PackedReciprocalReadCases) {
					t.Fatal("dead packed estimate object lost an original function", string(listing))
				}
				for index, section := range sections {
					end := len(listing)
					if index+1 < len(sections) {
						end = sections[index+1][0]
					}
					body := string(listing[section[1]:end])
					reads := regexp.MustCompile(`\b(?:v?rcpps|v?rsqrtps|v?mov[a-z0-9]*)\s+[^,\n]*\([^\n)]+\),[^\n]*`).FindAllString(body, -1)
					bank := "%xmm"
					if x86PackedReciprocalReadCases[index].width == 32 {
						bank = "%ymm"
					}
					access := false
					for _, read := range reads {
						access = access || strings.Contains(read, bank) && !strings.Contains(read, "%rsp") && !strings.Contains(read, "%rbp") && !strings.Contains(read, "%rip")
					}
					if !access {
						t.Errorf("actual object removed the original non-stack native access in %s:\n%s", listing[section[2]:section[3]], body)
					}
				}
			})
		}
	}
}
