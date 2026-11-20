package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestMMXMoveMaskCoverageRequiresDefinedSourceAndEMMS(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		registers := []string{"AX", "CX", "DX", "BX", "SI", "DI"}
		if arch == "amd64" {
			registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
		} else {
			registers = append(registers, "BP")
		}
		for bank := 0; bank < 8; bank++ {
			for _, destination := range registers {
				t.Run(fmt.Sprintf("%s/M%d/%s", arch, bank, destination), func(t *testing.T) {
					line := fmt.Sprintf("PMOVMSKB M%d,%s", bank, destination)
					instruction := compactProbeInstructions(t, line)[0]
					err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, instruction)
					if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
						t.Fatal("isolated physical MMX input became a zero-valued implementation slot", err)
					}
					stat := &formStat{}
					classifyFormProbe(stat, err)
					if stat.ContextCount != 1 || stat.SupportedCount != 0 || stat.UnsupportedCount != 0 {
						t.Fatal("missing MMX context changed the form classification", stat)
					}
					valueProbeNeedsContext(t, arch, line+"\nEMMS")
					// MOVL supplies all eight physical bytes, including its cleared
					// upper dword. The mask destination is write-only.
					initialized := fmt.Sprintf("MOVL $129,AX\nMOVL AX,M%d\n%s", bank, line)
					valueProbeNeedsContext(t, arch, initialized)
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, initialized+"\nEMMS")); err != nil {
						t.Fatal("defined, closed MMX sequence became unsupported", err)
					}
				})
			}
		}
	}
}
