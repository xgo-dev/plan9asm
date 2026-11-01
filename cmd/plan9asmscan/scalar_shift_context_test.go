package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScalarShiftMemoryCoverageRequiresAddressAndInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := []string{"B", "W", "L"}
		if arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, stem := range []string{"RCL", "RCR", "ROL", "ROR", "SAL", "SAR", "SHL", "SHR"} {
			for _, width := range widths {
				t.Run(arch+"/"+stem+width, func(t *testing.T) {
					for _, count := range []string{"$0", "$1", "CX"} {
						instruction := stem + width + " " + count + ",(DI)"
						valueProbeNeedsContext(t, arch, instruction)
						valueProbeNeedsContext(t, arch, "MOVL $1,DI\nMOVL $1,CX\nCLC\n"+instruction)
					}
					positive := "MOVL $1,AX\nMOVL $1,CX\nCLC\n" + stem + width + " CX,AX"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, compactProbeInstructions(t, positive)); err != nil {
						t.Error("initialized register counterpart lost support", err)
					}
				})
			}
		}
		for _, stem := range []string{"SARX", "SHLX", "SHRX", "RORX"} {
			for _, width := range []string{"L", "Q"} {
				t.Run(arch+"/"+stem+width, func(t *testing.T) {
					count := "CX"
					if stem == "RORX" {
						count = "$0"
					}
					instruction := stem + width + " " + count + ",(DI),AX"
					valueProbeNeedsContext(t, arch, instruction)
					valueProbeNeedsContext(t, arch, "MOVL $1,DI\nMOVL $1,CX\n"+instruction)
				})
			}
		}
	}
}
