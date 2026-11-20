package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func TestX86X87CorpusCompareInitializedCounterparts(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	const declaration = "func Value(left,right float64,p *float64) uint16"
	pkg := mustGoPackage(t, "comparecontext", "package comparecontext\n"+declaration)
	sig, err := DeriveGoFuncABI0Signature("Value", pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil || len(sig.Frame.Params) != 3 || len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Type != I16 {
		t.Fatal("actual compare declaration layout", sig, err)
	}
	for _, row := range []struct {
		instruction, pointer string
		depth                int
		direct, pop          bool
	}{
		{"FCOMD (BX),F0", "BX", 1, false, false},
		{"FCOMD (R11),F0", "R11", 1, false, false},
		{"FCOMD F2,F0", "", 3, false, false},
		{"FCOMD F3,F0", "", 4, false, false},
		{"FCOMI F2,F0", "", 3, true, false},
		{"FCOMI F3,F0", "", 4, true, false},
		{"FCOMIP F2,F0", "", 3, true, true},
		{"FCOMIP F3,F0", "", 4, true, true},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			prefix := "FINIT\n"
			if row.depth > 1 {
				prefix += fmt.Sprintf("FMOVD right+%d(FP),F0\n", sig.Frame.Params[1].Offset)
				prefix += strings.Repeat("FLD1\n", row.depth-2)
			}
			left := fmt.Sprintf("FMOVD left+%d(FP),F0\n", sig.Frame.Params[0].Offset)
			pointer := ""
			if row.pointer != "" {
				pointer = fmt.Sprintf("MOVQ p+%d(FP),%s\n", sig.Frame.Params[2].Offset, row.pointer)
			}
			capture := "FSTSW AX\n"
			if row.direct {
				// Capture all three predicates before shifts/OR overwrite FLAGS.
				capture = "MOVL $0,AX\nMOVL $0,CX\nMOVL $0,DX\nSETEQ AL\nSETCS CL\nSETPS DL\nSHLL $14,AX\nSHLL $8,CX\nSHLL $10,DX\nORL CX,AX\nORL DX,AX\n"
			}
			capture += fmt.Sprintf("ANDW $0x4500,AX\nMOVW AX,ret+%d(FP)\n", sig.Frame.Results[0].Offset)
			depth := row.depth
			if row.pop {
				depth--
			}
			finish := capture + strings.Repeat("FMOVDP F0,F0\n", depth) + "RET\n"
			for _, view := range []string{"initialized", "missing-value", "missing-pointer"} {
				if view == "missing-pointer" && row.pointer == "" {
					continue
				}
				body := prefix + left + pointer
				if view == "missing-value" {
					body = prefix + pointer
				} else if view == "missing-pointer" {
					body = prefix + left
				}
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s\n%s", sig.Frame.Results[0].Offset+2, body, row.instruction, finish)
				if view == "initialized" {
					if _, err := x86ScalarLiteralGoListing(t, "amd64", source); err != nil {
						t.Fatal("complete original Go compare source", err)
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(view+"/"+api, func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api, X87Hardware)
						if view != "initialized" {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unused typed arguments supplied missing actual compare inputs", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("exact initialized corpus operand form rejected", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, level)
						}
					})
				}
			}
		})
	}
}
