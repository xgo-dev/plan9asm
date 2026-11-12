package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestImplicitDivideCoverageRetainsAllInputsAndNativeFaults(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"DIVB", "DIVW", "DIVL", "DIVQ", "IDIVB", "IDIVW", "IDIVL", "IDIVQ"} {
			if arch == "386" && (op == "DIVQ" || op == "IDIVQ") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				valueProbeNeedsContext(t, arch, op+" BX")
				valueProbeNeedsContext(t, arch, "MOVL $7,AX\nMOVL $3,BX\n"+op+" (SI)")
				valueProbeNeedsContext(t, arch, "MOVL $3,BX\n"+op+" BX")
				prefix := "MOVL $7,AX\nMOVL $0,DX\nMOVL $3,BX\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, compactProbeInstructions(t, prefix+op+" BX")); err != nil {
					t.Fatal("fully initialized named register division lost its actual native opcode", err)
				}
				if op == "DIVB" || op == "IDIVB" {
					valueProbeNeedsContext(t, arch, "MOVB $7,AL\nMOVB $3,BL\n"+op+" BL")
				}
			})
		}
	}
}
