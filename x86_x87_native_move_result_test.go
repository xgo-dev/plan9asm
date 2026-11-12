package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86X87NativeMoveProgram(arch, op string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	load := strings.TrimSuffix(op, "P")
	body := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s src+0(FP),SI\n%s dst+%d(FP),DI\nFINIT\n%s 1(SI),F0\n%s F0,1(DI)\nFINIT\nMOVL $7,AX\nMOVL AX,ret+%d(FP)\nRET\n",
		2*word+4, move, move, word, load, op, 2*word)
	return body, "func Value(src,dst *byte) uint32"
}

func TestX86X87NativeFloatingMoveCompleteFamilyThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
			source, declaration := x86X87NativeMoveProgram(target.arch, op)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+op+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete x87 native floating move has an unclosed input/output rule", err)
					}
				})
			}
		}
	}
}

func TestX86X87NativeFloatingMoveMissingInputsAndDeadEffects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
			source, declaration := x86X87NativeMoveProgram(target.arch, op)
			for _, row := range []struct{ name, before, after string }{
				{"unknown-read-base", "1(SI),F0", "1(BX),F0"},
				{"unknown-read-index", "1(SI),F0", "1(SI)(CX*1),F0"},
				{"unknown-write-base", "F0,1(DI)", "F0,1(BX)"},
				{"unknown-F0", strings.TrimSuffix(op, "P") + " 1(SI),F0\n", ""},
			} {
				changed := strings.Replace(source, row.before, row.after, 1)
				if changed == source {
					t.Fatal("independent x87 mutation lost its source", row.name)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+op+"/"+row.name+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("x87 move invented source bytes or a native address", err)
						}
					})
				}
			}
		}
	}
}

func TestX86StackNativeValueReadsCompleteWidthsThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move, suffix := 8, "MOVQ", "Q"
		if target.arch == "386" {
			word, move, suffix = 4, "MOVL", "L"
		}
		for _, width := range []string{"W", suffix} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s src+0(FP),SI\nPUSH%s 1(SI)\nPOP%s AX\nMOVWLZX AX,AX\nMOVL AX,ret+%d(FP)\nRET\n", word+4, move, width, width, word)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+width+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(src *byte) uint32", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("native PUSH value did not consume its exact-width input", err)
					}
				})
			}
		}
	}
}

func TestX86X87NativeFloatingMoveCannotBypassVoidProof(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s dst+0(FP),DI\nFINIT\n%s F0,1(DI)\nFINIT\nRET\n", word, move, op)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+op+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(dst *byte)", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("discarded x87 results supplied unknown F0 bytes", err)
					}
				})
			}
		}
	}
}

func TestX86X87NativeFloatingMoveOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("x87 native floating moves require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		var source, declarations strings.Builder
		for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
			text, declaration := x86X87NativeMoveProgram(target.arch, op)
			source.WriteString(strings.ReplaceAll(text, "Value", op))
			declarations.WriteString(strings.ReplaceAll(declaration, "Value", op) + "\n")
		}
		requireX86GoAssemblerResult(t, target.arch, source.String(), true)
		for _, mode := range []X87Mode{X87Auto, X87Hardware, X87Software} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/mode%d/%s", target.triple, mode, api), func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source.String(), declarations.String(), target.arch, target.triple, api, mode)
					if err != nil || ir == "" {
						t.Fatal("complete original floating move source", err)
					}
					for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						for _, operation := range []string{"load", "store"} {
							for _, typ := range []string{"float", "double"} {
								if strings.Count(text, operation+" volatile "+typ) != 2 {
									t.Fatal("native floating move lost its exact width or observable access", operation, typ)
								}
							}
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		}
	}
}

func TestX86X87AndStackNativeReadsDoNotSupplyStandaloneBacking(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
			source, declaration := x86X87NativeMoveProgram(arch, op)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, "nativeinputs", "package nativeinputs\n"+declaration)
			sigs, err := goSigsForAsmFile(pkg, file, func(name string) string { return strings.TrimPrefix(name, "·") }, arch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if !errors.Is(check(file.Funcs[0], sigs["Value"], arch), ErrProbeNeedsContext) {
					t.Fatal("unpaired query acquired a native floating read/write", arch, op)
				}
			}
		}
		word, move, suffix := 8, "MOVQ", "Q"
		if arch == "386" {
			word, move, suffix = 4, "MOVL", "L"
		}
		for _, width := range []string{"W", suffix} {
			body := fmt.Sprintf("%s src+0(FP),SI\nPUSH%s 1(SI)\nPOP%s AX\nMOVWLZX AX,AX\nMOVL AX,ret+%d(FP)\nRET", move, width, width, word)
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(src *byte) uint32", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if !errors.Is(check(file.Funcs[0], sig, arch), ErrProbeNeedsContext) {
					t.Fatal("unpaired query acquired a native PUSH read", arch, width)
				}
			}
		}
	}
}
