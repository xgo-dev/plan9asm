package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestWaitPKGCoverageRequiresDeadlineAndControl(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"UMWAIT", "TPAUSE"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				for _, setup := range []string{"", "MOVL $0,AX\nMOVL $0,DX\n", "MOVL $0,BX\n",
					"MOVL $0,AX\nMOVL $0,BX\nMOVB $0,DL\n"} {
					valueProbeNeedsContext(t, arch, setup+op+" BX")
				}
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, "MOVL $0,AX\nMOVL $0,DX\nMOVL $0,BX\n"+op+" BX")); err != nil {
					t.Error("complete initialized wait rejected", err)
				}
			})
		}
	}
}
