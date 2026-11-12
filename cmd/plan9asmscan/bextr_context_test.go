package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestBEXTRCoverageRequiresActualControlAndSource(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BEXTRL", "BEXTRQ"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				row := op + " AX,BX,CX"
				valueProbeNeedsContext(t, arch, row)
				valueProbeNeedsContext(t, arch, op+" AX,(BX),CX")
				for _, prefix := range []string{
					"MOVW $0x0804,AX\n",
					"MOVB $4,AL\nMOVL $7,BX\n",
				} {
					valueProbeNeedsContext(t, arch, prefix+row)
				}
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, "MOVW $0x0804,AX\nMOVL $7,BX\n"+row)); err != nil {
					t.Fatal("initialized complete BEXTR form was classified as unsupported", err)
				}
			})
		}
	}
}
