package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ContinuationWholeCFGFiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("continuation object owner requires LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word := "Q"
			if target.arch == "386" {
				word = "L"
			}
			for _, dispatch := range []string{"memory", "register", "copied-target"} {
				t.Run(dispatch, func(t *testing.T) {
					source, options := x86ContinuationResultFixture(t, target.arch, true)
					options.TargetTriple = target.triple
					if dispatch != "memory" {
						body := " MOV" + word + " (SI),AX\n JMP AX"
						if dispatch == "copied-target" {
							body = " MOV" + word + " (SI),AX\n MOV" + word + " AX,CX\n MOV" + word + " $0,AX\n JMP CX"
						}
						source = strings.Replace(source, " JMP (SI)", body, 1)
					}
					if strings.Count(source, "TEXT ") != 4 || strings.Count(source, "GLOBL ") != 1 {
						t.Fatal("whole source fixture denominator changed")
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "owned-module"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ContinuationResultAPI(t, source, options, api)
							if err != nil {
								t.Fatal(err)
							}
							for _, optimized := range []bool{false, true} {
								input := ir
								if optimized {
									input = x86UndefinedTrapOptimizedIR(t, input)
								}
								for _, level := range []string{"-O0", "-O2"} {
									t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
										x86PackedStringCompileObject(t, llc, target.triple, input, level)
									})
								}
							}
							bad := strings.Replace(source, " MOV"+word+" BX,result+", " MOVB BX,result+", 1)
							if bad == source {
								t.Fatal("partial-result negative did not preserve/mutate complete source")
							}
							if output, err := x86ContinuationResultAPI(t, bad, options, api); output != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("a partial result escaped the coalesced whole-source proof", err)
							}
						})
					}
				})
			}
		})
	}
}
