package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestInLanePermuteCoverageRetainsActualInputsAndVoidReads(t *testing.T) {
	testElementPermuteCoverageInputs(t, []string{"VPERMILPS", "VPERMILPD"}, []string{"X", "Y", "Z"})
}

func TestQwordPermuteCoverageRetainsActualInputsAndVoidReads(t *testing.T) {
	testElementPermuteCoverageInputs(t, []string{"VPERMQ", "VPERMPD"}, []string{"Y", "Z"})
}

func testElementPermuteCoverageInputs(t *testing.T, members, banks []string) {
	t.Helper()
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range members {
			for _, bank := range banks {
				for _, immediate := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/immediate=%t", arch, op, bank, immediate), func(t *testing.T) {
						zero := "VPXOR"
						if bank == "Z" {
							zero = "VPXORD"
						}
						var prefix strings.Builder
						for register := 0; register < 3; register++ {
							fmt.Fprintf(&prefix, "%s %s%d,%s%d,%s%d\n", zero, bank, register, bank, register, bank, register)
						}
						operands, memory := bank+"0,"+bank+"1", "(AX),"+bank+"1"
						if immediate {
							operands, memory = "$0x1b,"+bank+"1", "$0x1b,(AX)"
						}
						row := op + " " + operands + "," + bank + "2"
						// A dead GP copy may correctly remain unknown. TEST
						// consumes its value and SETEQ consumes the resulting ZF,
						// as in the existing IFMA and AES scanner controls.
						observed := row + "\nMOVL X2,AX\nTESTL AX,AX\nSETEQ CX"
						valueProbeNeedsContext(t, arch, observed)
						if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
							compactProbeInstructions(t, prefix.String()+observed)); err != nil {
							t.Fatal("complete register data/selector input rejected", err)
						}
						// A numeric zero is not a native pointer, even when the
						// result is dead. Neither mask=0 nor broadcast repairs it.
						native := op + " " + memory + "," + bank + "2"
						valueProbeNeedsContext(t, arch, prefix.String()+native)
						valueProbeNeedsContext(t, arch, prefix.String()+"MOVL $0,AX\n"+native)
						if arch == "amd64" {
							masked := op + ".BCST.Z " + memory + ",K1," + bank + "2"
							valueProbeNeedsContext(t, arch, prefix.String()+"MOVL $0,AX\nKMOVD AX,K1\n"+masked)
						}
					})
				}
			}
		}
	}
}
