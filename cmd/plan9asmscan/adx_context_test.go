package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestADXCoverageRequiresBothOperandsAndSelectedCarry(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				line := op + " AX,BX"
				valueProbeNeedsContext(t, arch, line)
				prefix := "MOVL $3,AX\nMOVL $7,BX\nCMPL AX,AX\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+line)); err != nil {
					t.Fatal("complete initialized ADX sequence rejected", err)
				}
				for _, remove := range []string{"MOVL $3,AX\n", "MOVL $7,BX\n", "CMPL AX,AX\n"} {
					// Use a separate initialized comparison register so missing
					// AX cannot be hidden by the comparison's own input check.
					source := "MOVL $1,DX\n" + strings.Replace(prefix, "CMPL AX,AX", "CMPL DX,DX", 1) + line
					remove = strings.Replace(remove, "CMPL AX,AX", "CMPL DX,DX", 1)
					valueProbeNeedsContext(t, arch, strings.Replace(source, remove, "", 1))
				}
				valueProbeNeedsContext(t, arch, "MOVL $3,AX\nMOVL $7,BX\nCLC\nADOXL AX,BX")
			})
		}
	}
}
