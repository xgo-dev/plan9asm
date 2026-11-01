package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestSADCoverageRequiresActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, instruction := range []string{
			"PSADBW X0,X1", "MPSADBW $37,X0,X1", "VPSADBW Z0,Z1,Z2",
			"VMPSADBW $37,Y0,Y1,Y2", "VDBPSADBW.Z $37,Z0,Z1,K1,Z2",
		} {
			if arch == "386" && (strings.HasPrefix(instruction, "VMPS") || strings.HasPrefix(instruction, "VDBPS")) {
				continue // Go's named mode32 frontend has no four/five-operand row.
			}
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				valueProbeNeedsContext(t, arch, instruction)
				prefix := "MOVL $7,AX\nKMOVD AX,K1\n" +
					"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+instruction)); err != nil {
					t.Error("complete initialized SAD sequence rejected", err)
				}
				valueProbeNeedsContext(t, arch, strings.Replace(prefix+instruction, "VPXORD Z0,Z0,Z0\n", "", 1))
			})
		}
	}
}
