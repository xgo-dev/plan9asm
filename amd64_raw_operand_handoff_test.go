package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/x86/x86asm"
)

// This oracle assembles literal BYTE directives, not GoSyntax's synthetic
// memory spelling. Its complete contiguous text bytes independently anchor
// the private decoder input on both supported SDK test lanes.
func x86HandoffOriginalBytes(t *testing.T, arch string, code []byte) {
	t.Helper()
	source := "TEXT handoff(SB),4,$0-0\n" + x86RawDisplacementDirectives(code)
	listing, err := x86ScalarLiteralGoListing(t, arch, source)
	if err != nil {
		t.Fatal(err)
	}
	var actual []byte
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, err := strconv.ParseUint(fields[0][2:], 16, 32)
		if err != nil || int(offset) != len(actual) {
			t.Fatalf("noncontiguous stock Go bytes: %s", line)
		}
		// Both audited objfile.go printers use sixteen fixed three-byte
		// hex columns, then two spaces and ASCII. Never parse the ASCII
		// tail as another byte, even when it happens to be "ab" or "f.".
		text := strings.TrimLeft(line, "\t ")
		start := strings.IndexByte(text, ' ')
		if start < 0 || len(text) < start+48 {
			t.Fatalf("missing complete stock Go hex columns: %s", line)
		}
		gap := false
		for i := 0; i < 16; i++ {
			field := text[start+3*i : start+3*(i+1)]
			if field == "   " {
				gap = true
				continue
			}
			value, err := strconv.ParseUint(field[1:], 16, 8)
			if gap || field[0] != ' ' || err != nil {
				t.Fatalf("invalid stock Go hex column: %q", field)
			}
			actual = append(actual, byte(value))
		}
	}
	if !bytes.Equal(actual, code) {
		t.Fatalf("stock Go raw text = %x, want complete %x", actual, code)
	}
}

func TestX86PrivateDecoderX87PhysicalMemoryHandoff(t *testing.T) {
	forms := []struct {
		op   Op
		code []byte
	}{
		{"FSAVE", []byte{0xdd, 0x74, 0x8b, 0xf9}},
		{"FSTCW", []byte{0xd9, 0x7c, 0x8b, 0xf9}},
		{"FSTENV", []byte{0xd9, 0x74, 0x8b, 0xf9}},
		{"FSTSW", []byte{0xdd, 0x7c, 0x8b, 0xf9}},
		{"FLDCW", []byte{0xd9, 0x6c, 0x8b, 0xf9}},
		{"FLDENV", []byte{0xd9, 0x64, 0x8b, 0xf9}},
		{"FRSTOR", []byte{0xdd, 0x64, 0x8b, 0xf9}},
	}
	segments := []struct {
		prefix byte
		reg    Reg
	}{{0x26, ES}, {0x2e, CS}, {0x36, SS}, {0x3e, DS}, {0x64, FS}, {0x65, GS}}
	for _, arch := range []string{"386", "amd64"} {
		var complete []byte
		for _, form := range forms {
			for _, segment := range segments {
				complete = append(complete, segment.prefix)
				complete = append(complete, form.code...)
			}
		}
		complete = append(complete, 0xc3)
		x86HandoffOriginalBytes(t, arch, complete)
		for _, form := range forms {
			for _, segment := range segments {
				t.Run(arch+"/"+string(form.op)+"/"+string(segment.reg), func(t *testing.T) {
					code := append([]byte{segment.prefix}, form.code...)
					decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
					if err != nil {
						t.Fatal(err)
					}
					want := Operand{Kind: OpMem, Mem: MemRef{Base: BX, Index: CX, Scale: 4, Off: -7, Segment: segment.reg}}
					if arch == "amd64" && segment.reg != FS && segment.reg != GS {
						// In mode64 the actual decoder ignores the legacy flat
						// segment prefix; it supplies no physical override.
						want.Mem.Segment = ""
					}
					if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != form.op || len(decoded.Instrs[0].Args) != 1 || !reflect.DeepEqual(decoded.Instrs[0].Args[0], want) {
						t.Fatalf("physical memory changed: %+v, want %s %+v", decoded.Instrs, form.op, want)
					}
				})
			}
		}
	}
}

func TestX86PrivateDecoderImplicitPhysicalSegments(t *testing.T) {
	forms := []struct {
		name   string
		opcode byte
		source bool
		dest   bool
	}{
		{"MOVS", 0xa4, true, true}, {"CMPS", 0xa6, true, true},
		{"STOS", 0xaa, false, true}, {"LODS", 0xac, true, false},
		{"SCAS", 0xae, false, true}, {"INS", 0x6c, false, true},
		{"OUTS", 0x6e, true, false},
	}
	for _, mode := range []int{32, 64} {
		arch := "amd64"
		if mode == 32 {
			arch = "386"
		}
		var complete []byte
		for _, form := range forms {
			for _, segment := range []byte{0, 0x64, 0x65} {
				for _, repeat := range []byte{0, 0xf2, 0xf3} {
					code := []byte{0x67}
					if repeat != 0 {
						code = append(code, repeat)
					}
					if segment != 0 {
						code = append(code, segment)
					}
					code = append(code, form.opcode)
					complete = append(complete, code...)
				}
			}
		}
		complete = append(complete, 0xc3)
		x86HandoffOriginalBytes(t, arch, complete)
		for _, form := range forms {
			for _, segment := range []byte{0, 0x64, 0x65} {
				for _, repeat := range []byte{0, 0xf2, 0xf3} {
					t.Run(fmt.Sprintf("mode%d/%s/seg%02x/rep%02x", mode, form.name, segment, repeat), func(t *testing.T) {
						code := []byte{0x67}
						if repeat != 0 {
							code = append(code, repeat)
						}
						if segment != 0 {
							code = append(code, segment)
						}
						code = append(code, form.opcode)
						physical, err := x86asm.Decode(code, mode)
						if err != nil || physical.Len != len(code) {
							t.Fatalf("complete physical decode: %+v %v", physical, err)
						}
						instructions, err := x86AddressOverrideDecode(mode, code)
						if !form.source && segment != 0 {
							// x/arch does not mark this unused FS/GS prefix as
							// ignored. Do not guess or strip it: precise Context
							// replaces the old accidental source-parser failure.
							if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "unbound physical") {
								t.Fatalf("unbound physical prefix: %v", err)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						var memories []MemRef
						for _, ins := range instructions {
							if ins.Op == OpTEXT || ins.Op == OpRET {
								continue
							}
							if !ins.x86UnboundAddressOverride || ins.x86AddressBits != mode/2 {
								t.Fatalf("lost physical address restriction: %+v", ins)
							}
							for _, arg := range ins.Args {
								if arg.Kind == OpMem {
									memories = append(memories, arg.Mem)
								}
							}
							ctx, out := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
							ctx.goarch = arch
							before := out.String()
							if terminated, err := ctx.lowerInstr(0, 0, ins, nil, nil); terminated || !errors.Is(err, ErrProbeNeedsContext) || out.String() != before {
								t.Fatalf("unbound physical memory emitted IR: %t %v", terminated, err)
							}
						}
						wantSource := DS
						if segment == 0x64 {
							wantSource = FS
						} else if segment == 0x65 {
							wantSource = GS
						}
						seenSource, seenDest := false, false
						for _, memory := range memories {
							if memory.Base == SI && memory.Segment == wantSource {
								seenSource = true
							} else if memory.Base == DI && memory.Segment == ES {
								seenDest = true
							} else {
								t.Fatalf("unexpected implicit physical memory: %+v", memory)
							}
						}
						if seenSource != form.source || seenDest != form.dest {
							t.Fatalf("lost source/destination segments: %+v", memories)
						}
					})
				}
			}
		}
	}
}

func TestX86PrivateDecoderRIPPoolAllPublicAPIs(t *testing.T) {
	code := []byte{0x48, 0x8d, 0x05, 1, 0, 0, 0, 0xc3, 0x41}
	x86HandoffOriginalBytes(t, "amd64", code)
	file := mustParseX86RawReturn(t, x86StaticReturnSource("Bound", code))
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // RIP is a mode64-only machine addressing form.
		}
		opt := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
		for _, api := range []string{"text", "module", "owned-module"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				var ir string
				var err error
				switch api {
				case "text":
					ir, err = Translate(file, opt)
				case "module":
					module, callErr := TranslateModule(file, opt)
					err = callErr
					if err == nil {
						ir = module.String()
						module.Dispose()
					}
				default:
					ctx := llvm.NewContext()
					module, callErr := TranslateModuleInContext(ctx, file, opt)
					err = callErr
					if err == nil {
						ir = module.String()
						module.Dispose()
					}
					ctx.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM 22 llc required")
				}
				compileLLVMToObject(t, llc, target.triple, "handoff.ll", "handoff.o", ir)
			})
		}
	}
}

func TestX86PrivateDecoderX87FiveTargetObjects(t *testing.T) {
	// Object-only controls for the already-supported FS/GS address spaces.
	// They do not execute an unknown native pointer or prove caller bounds.
	var code []byte
	for _, opcode := range [][]byte{
		{0xdd, 0x30}, {0xd9, 0x38}, {0xd9, 0x30}, {0xdd, 0x38},
		{0xd9, 0x28}, {0xd9, 0x20}, {0xdd, 0x20},
		{0xdf, 0x20}, {0xdf, 0x30}, // packed BCD load/store
	} {
		for _, segment := range []byte{0x64, 0x65} {
			code = append(code, segment)
			code = append(code, opcode...)
		}
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			// This is the same named RET domain as the old x87 positive.
			// A raw RET plus unknown native memory remains Context.
			source := x86StaticReturnSource("Bound", code) +
				"FMOVX 0(AX)(FS),F0\nFMOVXP F0,0(AX)(FS)\n" +
				"FMOVX 0(AX)(GS),F0\nFMOVXP F0,0(AX)(GS)\nRET\n"
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			file := mustParseX86RawReturn(t, source)
			opt := Options{Goarch: target.arch, TargetTriple: target.triple, X87Mode: X87Software,
				Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
			for _, api := range []string{"text", "module", "owned-module"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86X87UnboundOriginalAPI(t, file, opt, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "FSAVE FS:0(AX)") {
						t.Fatal("complete original raw source acquired native AX/segment storage or an x87 image", err)
					}
				})
			}
			t.Run("lowerer-unit-object", func(t *testing.T) {
				ir := x86X87LowererObjectUnit(t, file, target.arch, target.triple)
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM 22 llc required")
				}
				compileLLVMToObject(t, llc, target.triple, "physical-x87-unit.ll", "physical-x87-unit.o", ir)
			})
		})
	}
}

func TestX86PrivateDecoderHandoffDoesNotWidenSourceOrLayout(t *testing.T) {
	for _, source := range []string{"FSAVE FS:0(AX)", "MOVSB DS:0(SI),ES:0(DI)", "LEAQ 1(IP),AX"} {
		t.Run("public/"+source, func(t *testing.T) {
			if _, err := Parse(ArchAMD64, "TEXT raw(SB),4,$0-0\n"+source+"\nRET\n"); err == nil {
				t.Fatal("private physical memory spelling became public source syntax")
			}
		})
	}
	for _, opcode := range [][]byte{{0xdd, 0x30}, {0xd9, 0x30}, {0xd9, 0x20}, {0xdd, 0x20}} {
		for _, mode := range []int{32, 64} {
			t.Run(fmt.Sprintf("legacy-layout/%d/%x", mode, opcode), func(t *testing.T) {
				code := append([]byte{0x66}, opcode...)
				arch := "amd64"
				if mode == 32 {
					arch = "386"
				}
				x86HandoffOriginalBytes(t, arch, append(append([]byte(nil), code...), 0xc3))
				_, err := decodeX86RawDirectives(rawX86Function(code), arch)
				if err == nil || !strings.Contains(err.Error(), "16-bit environment layout") {
					t.Fatalf("14/94-byte layout acquired the 28/108-byte alias: %v", err)
				}
			})
		}
	}
	code := []byte{0xd9, 0x20}
	inst, err := x86asm.Decode(code, 64)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*x86asm.Inst){
		"prefix": func(i *x86asm.Inst) { i.Prefix[0] = x86asm.PrefixFS },
		"size":   func(i *x86asm.Inst) { i.DataSize = 16 },
		"length": func(i *x86asm.Inst) { i.Len++ },
		"memory": func(i *x86asm.Inst) { i.Args[0] = x86asm.Mem{Base: x86asm.RBX} },
		"extra":  func(i *x86asm.Inst) { i.Args[1] = x86asm.RAX },
	} {
		t.Run("alias-witness/"+name, func(t *testing.T) {
			changed := inst
			mutate(&changed)
			if _, recognized, err := decodedX86X87EnvironmentLoad(changed, code); !recognized || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed decoded observation borrowed the environment alias: %v", err)
			}
		})
	}
	for _, changed := range [][]byte{{0xd9}, {0xd9, 0x28}, {0xd9, 0x20, 0x90}} {
		t.Run(fmt.Sprintf("alias-bytes/%x", changed), func(t *testing.T) {
			if _, recognized, err := decodedX86X87EnvironmentLoad(inst, changed); !recognized || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed encoding borrowed the environment alias: %v", err)
			}
		})
	}
	for _, code := range [][]byte{{0x67, 0x48, 0x8d, 0x05, 0, 0, 0, 0}, {0xf0, 0xd9, 0x20}} {
		t.Run(fmt.Sprintf("physical-boundary/%x", code), func(t *testing.T) {
			_, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
			if err == nil {
				t.Fatal("unbound EIP or invalid prefix acquired private memory admission")
			}
		})
	}
}

func TestX86PrivateDecoderNamedX87MemoryConsumers(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT Bound(SB),4,$0-0\n")
	var forms []string
	for _, segment := range []string{"FS", "GS"} {
		// Named FLDENV is the separately observed stock assembler defect
		// below, not an accepted object control. Its complete raw opcode
		// remains in the physical-memory and five-target object matrices.
		for _, op := range []string{"FSAVE", "FSTCW", "FSTENV", "FSTSW", "FLDCW", "FRSTOR"} {
			forms = append(forms, fmt.Sprintf("%s 0(AX)(%s)", op, segment))
		}
		for _, suffix := range []string{"B", "X", "F", "D", "W", "L", "V"} {
			forms = append(forms, fmt.Sprintf("FMOV%s 0(AX)(%s),F0", suffix, segment),
				fmt.Sprintf("FMOV%sP F0,0(AX)(%s)", suffix, segment))
		}
	}
	source.WriteString(strings.Join(forms, "\n") + "\n")
	source.WriteString("RET\n")
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			for _, form := range forms {
				t.Run("original-Go/"+form, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, target.arch, target.triple, "TEXT Bound(SB),4,$0-0\n"+form+"\nRET\n")
				})
			}
			if t.Failed() {
				return // Do not claim LLVM equivalence for a rejected Go input.
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			file := mustParseX86RawReturn(t, source.String())
			opt := Options{Goarch: target.arch, TargetTriple: target.triple, X87Mode: X87Software,
				Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
			for _, api := range []string{"text", "module", "owned-module"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86X87UnboundOriginalAPI(t, file, opt, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "FSAVE 0(AX)(FS)") {
						t.Fatal("complete original named source acquired native AX/segment storage or an x87 image", err)
					}
				})
			}
			t.Run("lowerer-unit-object", func(t *testing.T) {
				ir := x86X87LowererObjectUnit(t, file, target.arch, target.triple)
				for _, addressSpace := range []string{"ptr addrspace(256)", "ptr addrspace(257)"} {
					if !strings.Contains(ir, "getelementptr i8, "+addressSpace) || !strings.Contains(ir, "load i8, "+addressSpace) {
						t.Fatalf("environment/BCD emitter unit lost %s", addressSpace)
					}
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM 22 llc required")
				}
				compileLLVMToObject(t, llc, target.triple, "named-x87-unit.ll", "named-x87-unit.o", ir)
			})
		})
	}
}

func TestX86PrivateDecoderNamedFLDENVStockGoDefect(t *testing.T) {
	// Do not turn a positionless backend defect into a generic source-rejection
	// certificate. Bind the entire one-instruction fixture and exact process
	// outcome separately; raw D9 /4 is independently accepted above.
	for _, target := range x86RawReturnTargets {
		for _, segment := range []string{"FS", "GS"} {
			t.Run(target.triple+"/"+segment, func(t *testing.T) {
				original := "TEXT Bound(SB),4,$0-0\nFLDENV 0(AX)(" + segment + ")\nRET\n"
				dir := t.TempDir()
				input, object := filepath.Join(dir, "fldenv.s"), filepath.Join(dir, "fldenv.o")
				if err := os.WriteFile(input, []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				stage, cancelStage := runtimeOracleStageContext(t)
				defer cancelStage()
				ctx, cancel := context.WithTimeout(stage, 30*time.Second)
				defer cancel()
				driver, driverHash := x86LEAActualSDKDriver(t)
				goos := "linux"
				if strings.Contains(target.triple, "apple") {
					goos = "darwin"
				} else if strings.Contains(target.triple, "windows") {
					goos = "windows"
				}
				command := exec.CommandContext(ctx, driver, "tool", "asm", "-p", "sourceframe", "-o", object, input)
				command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
					"GOOS="+goos, "GOARCH="+target.arch, "CGO_ENABLED=0")
				output, err := runtimeOracleCombinedOutput(ctx, command)
				const diagnostic = "asm: asmand: bad address \nasm: assembly failed\n"
				if failure := x86UnnamedAsmidxOutcome(output, err, ctx.Err(), diagnostic); failure != nil {
					t.Fatalf("unknown named FLDENV backend observation: %v\n%s", failure, output)
				}
				if goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), false, target.arch) == nil {
					t.Fatal("positionless backend defect became a source-rejection certificate")
				}
				for _, changed := range []string{"", diagnostic + diagnostic, diagnostic + "unexpected\n", "asm: assembly failed\n"} {
					if x86UnnamedAsmidxOutcome([]byte(changed), err, nil, diagnostic) == nil {
						t.Fatal("changed/missing/repeated backend diagnostic accepted")
					}
				}
				for _, changed := range []error{nil, errors.New("tool launch"), errors.Join(err, errors.New("cleanup"))} {
					if x86UnnamedAsmidxOutcome(output, changed, nil, diagnostic) == nil {
						t.Fatal("missing/unknown/cleanup process failure accepted")
					}
				}
				if x86UnnamedAsmidxOutcome(output, err, context.DeadlineExceeded, diagnostic) == nil {
					t.Fatal("expired backend observation accepted")
				}
				if data, readErr := os.ReadFile(input); readErr != nil || string(data) != original {
					t.Fatal("original named FLDENV source changed", readErr)
				}
				t.Logf("GO_BACKEND_DEFECT not-source-exclusion target=%s source=%q sourceSHA=%x driverSHA=%s diagnosticSHA=%x",
					target.triple, original, sha256.Sum256([]byte(original)), driverHash, sha256.Sum256(output))
			})
		}
	}
}

func TestX86PrivateDecoderUnboundSegmentCannotEmit(t *testing.T) {
	// These are exactly the eighteen old parser-error controls: mode32
	// STOSB/STOSL/INSB/INSL and mode64 plus STOSQ, each with FS/GS. They
	// remain unbound machine Context, not new public syntax or object passes.
	for _, target := range x86RawReturnTargets {
		forms := [][]byte{{0xaa}, {0xab}, {0x6c}, {0x6d}}
		mode := 32
		if target.arch == "amd64" {
			mode = 64
			forms = append(forms, []byte{0x48, 0xab})
		}
		for _, opcode := range forms {
			for _, segment := range []byte{0x64, 0x65} {
				code := append([]byte{0x67, segment}, opcode...)
				physical, err := x86asm.Decode(code, mode)
				if err != nil || physical.Len != len(code) {
					t.Fatal("complete segment observation", physical, err)
				}
				memory, ok := physical.Args[0].(x86asm.Mem)
				if !ok || memory.Segment != x86asm.ES || physical.Prefix[1]&x86asm.PrefixIgnored != 0 {
					t.Fatal("unbound prefix borrowed an ignored/default-segment identity", physical)
				}
				for _, api := range []string{"text", "module", "owned-module"} {
					t.Run(fmt.Sprintf("%s/%x/%s", target.triple, code, api), func(t *testing.T) {
						file := mustParseX86RawReturn(t, x86StaticReturnSource("Bound", code)+"RET\n")
						opt := Options{Goarch: target.arch, TargetTriple: target.triple,
							Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: Void}}}
						var callErr error
						switch api {
						case "text":
							ir, err := Translate(file, opt)
							callErr = err
							if ir != "" {
								t.Fatal("unbound segment emitted text")
							}
						case "module":
							module, err := TranslateModule(file, opt)
							callErr = err
							if !module.IsNil() {
								module.Dispose()
								t.Fatal("unbound segment emitted a module")
							}
						default:
							ctx := llvm.NewContext()
							module, err := TranslateModuleInContext(ctx, file, opt)
							callErr = err
							if !module.IsNil() {
								module.Dispose()
								ctx.Dispose()
								t.Fatal("unbound segment emitted an owned module")
							}
							ctx.Dispose()
						}
						if !errors.Is(callErr, ErrProbeNeedsContext) || !strings.Contains(callErr.Error(), "unbound physical") {
							t.Fatalf("unbound segment lost Context: %v", callErr)
						}
					})
				}
			}
		}
	}
}
