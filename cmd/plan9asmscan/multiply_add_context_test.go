package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestMultiplyAddCoverageRequiresInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []string{"PMADDWL", "PMADDUBSW", "VPMADDWD", "VPMADDUBSW"} {
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				register, memory := opcode+" X0,X1", opcode+" (BX),X1"
				if strings.HasPrefix(opcode, "V") {
					register, memory = register+",X2", memory+",X2"
				}
				valueProbeNeedsContext(t, arch, register)
				valueProbeNeedsContext(t, arch, memory)
				prefix := "PXOR X0,X0\nPXOR X1,X1\nMOVL $1,BX\n"
				valueProbeNeedsContext(t, arch, prefix+memory)
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+register)); err != nil {
					t.Fatal("complete initialized register form lost support", err)
				}
			})
		}
	}
}
