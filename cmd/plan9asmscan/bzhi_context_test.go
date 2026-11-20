package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestBZHICoverageRequiresActualIndexAndSource(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BZHIL", "BZHIQ"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				for _, source := range []string{
					op + " AX,BX,CX",
					op + " AX,(BX),CX",
					"MOVB $4,AH\nMOVL $7,BX\n" + op + " AX,BX,CX",
					"MOVB $0,AL\n" + op + " AX,BX,CX",
				} {
					valueProbeNeedsContext(t, arch, source)
				}
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, "MOVB $4,AL\nMOVL $7,BX\n"+op+" AX,BX,CX")); err != nil {
					t.Fatal("initialized low-byte BZHI source classified as unsupported", arch, op, err)
				}
			})
		}
	}
}
