package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestSqrtCoverageRequiresActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []string{
			"SQRTSS X0,X2", "SQRTSD X0,X2", "SQRTPS X0,X2", "SQRTPD X0,X2",
			"VSQRTSS X0,X1,X2", "VSQRTSD X0,X1,X2", "VSQRTPS.Z Z0,K1,Z2", "VSQRTPD.Z Y0,K1,Y2",
		} {
			t.Run(arch+"/"+row, func(t *testing.T) {
				valueProbeNeedsContext(t, arch, row)
				prefix := "MOVL $7,AX\nKMOVD AX,K1\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+row)); err != nil {
					t.Fatal("complete sqrt input rejected", err)
				}
				valueProbeNeedsContext(t, arch, strings.Replace(prefix+row, "VPXORD Z0,Z0,Z0\n", "", 1))
			})
		}
	}
}
