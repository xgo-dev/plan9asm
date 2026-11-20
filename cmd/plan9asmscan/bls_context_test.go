package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestBLSCoverageRequiresActualSourceBytes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BLSIL", "BLSIQ", "BLSMSKL", "BLSMSKQ", "BLSRL", "BLSRQ"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				row := op + " AX,BX"
				valueProbeNeedsContext(t, arch, row)
				valueProbeNeedsContext(t, arch, op+" (AX),BX")
				valueProbeNeedsContext(t, arch, "MOVB $7,AL\n"+row)
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, "MOVL $7,AX\n"+row)); err != nil {
					t.Fatal("initialized BLS source classified as unsupported", arch, op, err)
				}
			})
		}
	}
}
