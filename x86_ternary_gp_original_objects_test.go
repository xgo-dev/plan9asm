package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86TernaryGPOriginalRuntimeObjects(t *testing.T) {
	parallel, _, _, _ := x86ParallelBitsOriginalRuntimeFixture(t)
	for _, row := range []struct{ name, source, declaration string }{
		{"ANDN", x86ANDNOriginalRuntimeSource, "func andnsemantics(out *[40]byte)"},
		{"parallel", parallel.String(), x86ParallelBitsOriginalDeclarations()},
	} {
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			t.Run(row.name+"/"+triple, func(t *testing.T) {
				x86RawNumericalFamilyObjects(t, row.source, row.declaration, "amd64", triple)
			})
		}
	}
}

func TestX86YmlYrlYrlInitializedFiveTargetObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			if word == 4 {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, op := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
				for _, memory := range []bool{false, true} {
					for _, raw := range []bool{false, true} {
						name, first := fmt.Sprintf("Value%d", count), "AX"
						if memory {
							first = "(SI)"
						}
						line := op + " " + first + ",BX,CX"
						if raw {
							line = x86RawNumericalInstruction(t, target.arch, line)
						}
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s value+0(FP),AX\n%s input+%d(FP),SI\n%s $-1,BX\n%s\n%s CX,ret+%d(FP)\nRET\n", name, word*3, move, move, word, move, line, move, word*2)
						fmt.Fprintf(&declarations, "func %s(value uintptr,input *[8]byte) uintptr\n", name)
						count++
					}
				}
			}
			if count != 24 {
				t.Fatal("complete six-member named/raw register/memory grammar changed", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}

func x86ParallelBitsOriginalDeclarations() string {
	var declarations string
	for index := 0; index < 24; index++ {
		declarations += fmt.Sprintf("func parallelbits%d(value uint64,mask *uint64,out *[16]byte)\n", index)
	}
	return declarations
}
