package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86MaskNativeEmitterPreservesExactVolatileWidths(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ResultMaskMoveWidthOracle {
			for _, text := range []string{row.op + " 3(AX)(CX*2),K1", row.op + " K1,3(AX)(CX*2)"} {
				t.Run(arch+"/"+text, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, text)
					consumer, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
					consumer.goarch = arch
					// Emitter unit only: entry register values here are not a
					// source proof, native backing or executable input.
					if err := consumer.lowerMaskMove(ins.Op, ins); err != nil {
						t.Fatal(err)
					}
					operation := "load"
					if ins.Args[0].Kind == OpReg {
						operation = "store"
					}
					if strings.Count(output.String(), fmt.Sprintf("%s volatile i%d", operation, row.bits)) != 1 ||
						!strings.Contains(output.String(), "align 1") {
						t.Fatal("native mask effect lost its exact width, fault or unaligned role", output.String())
					}
				})
			}
		}
	}
}

func x86MaskNativeFixture(arch, op string, dead bool) (string, string) {
	move, word := "MOVQ", 8
	if arch == "386" {
		move, word = "MOVL", 4
	}
	result := "KMOVD K1,BX\n"
	if dead {
		result = "MOVL $7,BX\n"
	}
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,CX\n"+
		"%s 3(AX)(CX*2),K1\n%s K1,3(AX)(CX*2)\n%sMOVL BX,ret+%d(FP)\nRET\n",
		word+4, move, op, op, result, word)
	return source, "func Value(p *[16]byte) uint32"
}

func TestX86MaskNativeCompleteFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range x86ResultMaskMoveWidthOracle {
			for _, dead := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/dead%t", target.triple, row.op, dead), func(t *testing.T) {
					source, declaration := x86MaskNativeFixture(target.arch, row.op, dead)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("paired native mask movement rejected", api, err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							if strings.Count(text, fmt.Sprintf("load volatile i%d,", row.bits)) != 1 ||
								strings.Count(text, fmt.Sprintf("store volatile i%d ", row.bits)) != 1 {
								t.Fatal("live/dead optimized source lost a native read or write", api, text)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86MaskNativeCannotSupplyDeclarationOrMissingInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86ResultMaskMoveWidthOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				source, declaration := x86MaskNativeFixture(arch, row.op, false)
				body := strings.SplitN(strings.TrimSuffix(source, "RET\n"), "\n", 2)[1]
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, declaration, body)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("standalone declaration borrowed native execution", err)
					}
				}
				for name, changed := range map[string]string{
					"unknown-base":  strings.Replace(source, "p+0(FP),AX", "p+0(FP),DI", 1),
					"numeric-base":  strings.Replace(source, "MOVL $1,CX", "MOVL $42,AX\nMOVL $1,CX", 1),
					"unknown-index": strings.Replace(source, "MOVL $1,CX\n", "", 1),
					"unknown-mask":  strings.Replace(source, row.op+" 3(AX)(CX*2),K1\n", "", 1),
				} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("native mask movement invented missing facts", name, api, err)
						}
					}
				}
			})
		}
	}
}
