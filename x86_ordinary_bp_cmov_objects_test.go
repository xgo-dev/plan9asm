package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func x86RequireCMOVVolatileWidth(t *testing.T, ir string, bytes, count int) {
	t.Helper()
	// The original byte vector may be folded into the same-width scalar by
	// real LLVM optimization. Neither widening nor erasing a volatile read is valid.
	pattern := fmt.Sprintf(`load volatile (?:<%d x i8>|i%d),`, bytes, bytes*8)
	if got := len(regexp.MustCompile(pattern).FindAllString(ir, -1)); got != count {
		t.Fatal("CMOV did not preserve the complete unconditional native read width", bytes, got, count)
	}
}

func TestX86OrdinaryBPCMOVCompleteFamilyGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	names := x86CMOVOracleNames("386")
	if len(names) != 32 {
		t.Fatal("complete W/L x16 condition family changed", len(names))
	}
	targets, sources, originals, objects := 0, 0, 0, 0
	for _, target := range x86OrderingHintTargets {
		if target.arch != "386" {
			continue // SP and AMD64 BP remain physical source-frame boundaries.
		}
		targets++
		t.Run(target.triple, func(t *testing.T) {
			for _, frame := range []int{0, 64} {
				t.Run(fmt.Sprint(frame), func(t *testing.T) {
					var source, declarations strings.Builder
					for index, name := range names {
						for variant, address := range []string{"(BP)", "(SI)(BP*1)"} {
							function := fmt.Sprintf("cmovBP%d_%d", index, variant)
							setup := "MOVL p+0(FP),BP\n"
							if variant == 1 {
								setup = "MOVL p+0(FP),SI\nMOVL $0,BP\n"
							}
							fmt.Fprintf(&source, "TEXT ·%s(SB),4,$%d-4\n%sMOVL $7,AX\nCMPL AX,$0\n%s %s,AX\nRET\n", function, frame, setup, name, address)
							fmt.Fprintf(&declarations, "func %s(p *byte)\n", function)
							sources++
						}
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					originals++
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), "package ordering\n"+declarations.String(), target.arch, target.triple)
							if err != nil {
								t.Fatal("complete ordinary BP CMOV family", err)
							}
							for _, optimized := range []bool{false, true} {
								t.Run(fmt.Sprintf("optimized=%t", optimized), func(t *testing.T) {
									input := ir
									if optimized {
										input = x86MulDivRoundOptimize(t, input)
									}
									x86RequireCMOVVolatileWidth(t, input, 2, 32)
									x86RequireCMOVVolatileWidth(t, input, 4, 32)
									compileLLVMToObject(t, llc, target.triple, "native-bp-cmov.ll", "native-bp-cmov.o", input)
									objects++
								})
							}
						})
					}
				})
			}
		})
	}
	if targets != 2 || sources != 256 || originals != 4 || objects != 24 {
		t.Fatal("complete CMOV width/condition/address/frame/target/API union changed", targets, sources, originals, objects)
	}
	t.Log("32 W/L conditions,256 source functions,4 original Go objects,24 LLVM22 objects; compile-only")
}
