package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

var x86Reciprocal14TestMembers = []struct {
	op     string
	bits   int
	scalar bool
}{
	{"VRCP14PS", 32, false}, {"VRCP14PD", 64, false},
	{"VRCP14SS", 32, true}, {"VRCP14SD", 64, true},
	{"VRSQRT14PS", 32, false}, {"VRSQRT14PD", 64, false},
	{"VRSQRT14SS", 32, true}, {"VRSQRT14SD", 64, true},
}

func TestX86OfficialReciprocal14RowsInitializedThreeAPIsObjects(t *testing.T) {
	x86OfficialPackedRowsObjects(t, goasmrules.X86Reciprocal14Rows, 32, 132, 0)
}

func TestX86Reciprocal14FeatureProjection(t *testing.T) {
	for _, member := range x86Reciprocal14TestMembers {
		for _, bank := range []string{"X", "Y", "Z"} {
			if member.scalar && bank != "X" {
				continue
			}
			instruction := x86Reciprocal14TestInstruction(member.op, bank+"16", bank, "plain", member.scalar)
			ins := x86ScalarLaneInstruction(t, instruction)
			features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", Func{Instrs: []Instr{ins}})
			if !strings.Contains(features, "+avx512f") || strings.Contains(features, "+avx512vl") != (!member.scalar && bank != "Z") {
				t.Errorf("feature projection does not follow the complete source shape: %s: %s", instruction, features)
			}
		}
	}
}

func x86Reciprocal14TestInstruction(op, source, bank, mode string, scalar bool) string {
	operands := source + ","
	if scalar {
		operands += "X17,"
	}
	if mode != "plain" {
		operands += "K1,"
	}
	if mode == "zero" {
		op += ".Z"
	}
	return op + " " + operands + bank + "18"
}

func TestX86Reciprocal14TypedCompleteFamilyRoles(t *testing.T) {
	for _, member := range x86Reciprocal14TestMembers {
		banks := []string{"X", "Y", "Z"}
		if member.scalar {
			banks = banks[:1]
		}
		for _, bank := range banks {
			for _, mode := range []string{"plain", "merge", "zero"} {
				for _, memory := range []bool{false, true} {
					source := bank + "16"
					if memory {
						source = "(AX)"
					}
					instruction := x86Reciprocal14TestInstruction(member.op, source, bank, mode, member.scalar)
					t.Run(instruction, func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, instruction)
						effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
						if !known || err != nil || !effect.requiresResultProof || effect.vector.upperWrite != x86TypedVectorUpperZero ||
							effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
							t.Fatal("complete reciprocal14 has no precise typed owner", known, err, effect)
						}
						width := int64(map[string]int{"X": 16, "Y": 32, "Z": 64}[bank])
						for _, operand := range effect.operands {
							switch operand.index {
							case 0:
								if member.scalar {
									width = int64(member.bits / 8)
								}
								if !operand.read || operand.write || operand.width != width {
									t.Fatal("reciprocal14 numerical source width changed", operand)
								}
							case len(ins.Args) - 1:
								if !operand.write || operand.read != (mode == "merge") || member.scalar && operand.read &&
									operand.requiredBytes != x86CallerVectorByteMask(int64(member.bits/8)) {
									t.Fatal("old destination is not exactly the merging result bytes", operand)
								}
							case 1:
								if member.scalar && (!operand.read || operand.write || operand.width != 16 ||
									operand.requiredBytes != 0xffff&^x86CallerVectorByteMask(int64(member.bits/8))) {
									t.Fatal("scalar passthrough acquired an unused low input", operand)
								}
							}
						}
						if len(effect.operands) != len(ins.Args) {
							t.Fatal("reciprocal14 lost an explicit source/result/mask role", effect)
						}
					})
				}
			}
		}
	}
}

func TestX86Reciprocal14InitializedAndMissingInputsThreeAPIs(t *testing.T) {
	for index, member := range x86Reciprocal14TestMembers {
		for _, memory := range []bool{false, true} {
			sourceOperand := "X16"
			if memory {
				sourceOperand = "(AX)"
			}
			instruction := x86Reciprocal14TestInstruction(member.op, sourceOperand, "X", "zero", member.scalar)
			source, declaration := x86PackedAbsSignInitializedInstruction(index, instruction, "amd64", [3]int{16, 17, 18})
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(instruction+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("initialized reciprocal14 program was rejected", err)
					}
					withoutOld := strings.Replace(source, "VMOVDQU64 (CX),Z18\n", "", 1)
					if ir, err := x86ScalarFPBitViewAPI(t, withoutOld, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
						t.Fatal("zeroing operation borrowed an old destination", err)
					}
					missing := []string{"KMOVQ mask+32(FP),K1\n"}
					if !memory {
						missing = append(missing, "VMOVDQU64 (AX),Z16\n")
					}
					if member.scalar {
						missing = append(missing, "VMOVDQU64 (BX),Z17\n")
					}
					for _, input := range missing {
						negative := strings.Replace(source, input, "", 1)
						if negative == source {
							t.Fatal("undefined-input control did not remove its source", input)
						}
						ir, err = x86ScalarFPBitViewAPI(t, negative, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("reciprocal14 borrowed an absent numerical/upper/mask input", input, err)
						}
					}
				})
			}
		}
	}
}

func TestX86Reciprocal14ScalarUpperDoesNotReadLowPassthrough(t *testing.T) {
	for index, member := range x86Reciprocal14TestMembers {
		if !member.scalar {
			continue
		}
		instruction := member.op + " X16,X1,X18"
		source, declaration := x86PackedAbsSignInitializedInstruction(index, instruction, "amd64", [3]int{16, 17, 18})
		upper := "MOVQ $123,R8\nPINSRQ $1,R8,X1\n"
		if member.bits == 32 {
			upper = "MOVL $123,R8\nPINSRD $1,R8,X1\nPINSRD $2,R8,X1\nPINSRD $3,R8,X1\n"
		}
		source = strings.Replace(source, "VMOVDQU64 (BX),Z17\n", upper, 1)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(member.op+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Fatal("unused low passthrough was required as a numerical input", err)
				}
			})
		}
	}
}

func TestX86Reciprocal14DynamicMXCSRActualOptimizedObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required")
	}
	var source, declarations strings.Builder
	for index, member := range x86Reciprocal14TestMembers {
		name := fmt.Sprint("Environment", index)
		fmt.Fprintf(&declarations, "func %s(out *[32]byte,input,upper *[16]byte,first,second *uint32)\n", name)
		instruction := x86Reciprocal14TestInstruction(member.op, "X16", "X", "plain", member.scalar)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-40\nMOVQ out+0(FP),DI\nMOVQ input+8(FP),AX\n"+
			"MOVQ upper+16(FP),BX\nMOVQ first+24(FP),CX\nMOVQ second+32(FP),DX\n"+
			"VMOVUPS (AX),X16\nVMOVUPS (BX),X17\nLDMXCSR (CX)\n%s\nVMOVUPS X18,(DI)\n"+
			"LDMXCSR (DX)\n%s\nVMOVUPS X18,16(DI)\nRET\n", name, instruction, instruction)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", "Go")
	if err != nil {
		t.Fatal("initialized dynamic MXCSR source rejected", err)
	}
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			body, level := ir, "-O0"
			if optimized {
				body, level = x86DwordProductIROptimize(t, ir), "-O2"
			}
			directory := t.TempDir()
			input, object := filepath.Join(directory, "environment.ll"), filepath.Join(directory, "environment.o")
			if err := os.WriteFile(input, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", input, "-o", object))
			listing := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "--disassemble", object))
			x86Reciprocal14RetainObject(t, source.String(), declarations.String(), body, object, listing)
			for _, member := range x86Reciprocal14TestMembers {
				count := len(regexp.MustCompile(`\b`+strings.ToLower(member.op)+`\b`).FindAll(listing, -1))
				if count != 2 {
					t.Errorf("two equal register inputs with distinct MXCSR environments became %d %s instructions in actual object:\n%s", count, member.op, listing)
				}
			}
			sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <([^>]+)>:\n`).FindAllSubmatchIndex(listing, -1)
			seen := map[string]bool{}
			for sectionIndex, section := range sections {
				name := string(listing[section[2]:section[3]])
				for index, member := range x86Reciprocal14TestMembers {
					if name != fmt.Sprint("Environment", index) {
						continue
					}
					end := len(listing)
					if sectionIndex+1 < len(sections) {
						end = sections[sectionIndex+1][0]
					}
					op := strings.ToLower(member.op)
					sequence := regexp.MustCompile(`\b(ldmxcsr|`+op+`)\b`).FindAllString(string(listing[section[1]:end]), -1)
					if strings.Join(sequence, ",") != "ldmxcsr,"+op+",ldmxcsr,"+op {
						t.Errorf("dynamic environment order changed in %s: %v", name, sequence)
					}
					seen[name] = true
				}
			}
			if len(seen) != len(x86Reciprocal14TestMembers) {
				t.Fatal("dynamic environment object lost a function", seen)
			}
		})
	}
}

func TestX86Reciprocal14BackendBoundaryThreeAPIs(t *testing.T) {
	for index, member := range x86Reciprocal14TestMembers {
		instruction := x86Reciprocal14TestInstruction(member.op, "X16", "X", "plain", member.scalar)
		source, declaration := x86PackedAbsSignInitializedInstruction(index, instruction, "amd64", [3]int{16, 17, 18})
		for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-wasi", "unknown-unknown-wasm32", "i386-unknown-linux-gnu"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(member.op+"/"+triple+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("native reciprocal14 escaped its matching backend", err)
					}
				})
			}
		}
	}
}

func TestX86Reciprocal14MaskedDeadMemoryActualOptimizedObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required")
	}
	var source, declarations strings.Builder
	for index, member := range x86Reciprocal14TestMembers {
		for modeIndex, mode := range []string{"merge", "zero"} {
			instruction := x86Reciprocal14TestInstruction(member.op, "(AX)", "X", mode, member.scalar)
			body, declaration := x86PackedAbsSignInitializedInstruction(index*2+modeIndex, instruction, "amd64", [3]int{16, 17, 18})
			// The memory source must be read only by the instruction under test;
			// a separate register initializer would conceal its lost access.
			body = strings.Replace(body, "VMOVDQU64 (AX),Z16\n", "", 1)
			body = strings.Replace(body, "VMOVDQU64 Z18,(DI)\nSETCS 64(DI)\n", "", 1)
			source.WriteString(body)
			declarations.WriteString(declaration)
		}
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", "Go")
	if err != nil {
		t.Fatal("initialized dead masked-memory program rejected", err)
	}
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			body, level := ir, "-O0"
			if optimized {
				body, level = x86DwordProductIROptimize(t, ir), "-O2"
			}
			directory := t.TempDir()
			input, object := filepath.Join(directory, "dead-memory.ll"), filepath.Join(directory, "dead-memory.o")
			if err := os.WriteFile(input, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", input, "-o", object))
			listing := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "--disassemble", object))
			x86Reciprocal14RetainObject(t, source.String(), declarations.String(), body, object, listing)
			for _, member := range x86Reciprocal14TestMembers {
				count := len(regexp.MustCompile(`\b`+strings.ToLower(member.op)+`\b[^\n]*\(`).FindAll(listing, -1))
				if count != 2 {
					t.Errorf("dead results retained %d of two masked native-memory %s operations in actual object:\n%s", count, member.op, listing)
				}
			}
		})
	}
}

func x86Reciprocal14RetainObject(t *testing.T, source, declaration, ir, object string, listing []byte) {
	t.Helper()
	root := os.Getenv("PLAN9ASM_RUNTIME_ARTIFACT_DIR")
	if root == "" {
		return
	}
	directory := filepath.Join(root, t.Name())
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"source.s": []byte(source), "declarations.go": []byte(declaration),
		"module.ll": []byte(ir), "module.o": bytes, "module.disassembly": listing,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
