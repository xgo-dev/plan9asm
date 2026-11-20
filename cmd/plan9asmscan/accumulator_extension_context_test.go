package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestAccumulatorExtensionCoverageRequiresActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		names := []string{"CBW", "CWDE", "CWD", "CDQ"}
		if arch == "amd64" {
			names = append(names, "CDQE", "CQO")
		}
		for _, name := range names {
			t.Run(arch+"/"+name, func(t *testing.T) {
				valueProbeNeedsContext(t, arch, name)
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, "MOVL $7,AX\n"+name)); err != nil {
					t.Fatal("initialized complete accumulator extension rejected", err)
				}
			})
		}
	}
}
