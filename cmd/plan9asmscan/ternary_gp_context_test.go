package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestTernaryGPCoverageRequiresBothActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				line := op + " AX,BX,CX"
				prefix := "MOVL $3,AX\nMOVL $7,BX\n"
				valueProbeNeedsContext(t, arch, line)
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+line)); err != nil {
					t.Fatal("initialized complete ternary GP sequence rejected", err)
				}
				for _, remove := range []string{"MOVL $3,AX\n", "MOVL $7,BX\n"} {
					valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, remove, "", 1))
				}
				if strings.HasPrefix(op, "ANDN") {
					valueProbeNeedsContext(t, arch, prefix+line+"\nSETPS AX")
				}
			})
		}
	}
}
