package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestMaskLogicalCoverageRequiresCompleteInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{"KAND", "KANDN", "KOR", "KXNOR", "KXOR", "KNOT", "KTEST", "KORTEST"} {
			for _, suffix := range []string{"B", "W", "D", "Q"} {
				t.Run(arch+"/"+stem+suffix, func(t *testing.T) {
					operands := "K1,K2,K3"
					if stem == "KNOT" || strings.Contains(stem, "TEST") {
						operands = "K1,K2"
					}
					instruction := stem + suffix + " " + operands
					valueProbeNeedsContext(t, arch, instruction)
					prefix := "MOVL $3,AX\nKMOVD AX,K1\nKMOVD AX,K2\n"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+instruction)); err != nil {
						t.Error("complete initialized mask logical source rejected", err)
					}
					valueProbeNeedsContext(t, arch, strings.Replace(prefix+instruction, "KMOVD AX,K1\n", "", 1))
				})
			}
		}
	}
}
