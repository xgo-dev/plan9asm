package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestVectorTestCoverageRequiresActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"PTEST", "VPTEST", "VTESTPD", "VTESTPS"} {
			banks := []string{"X"}
			if name != "PTEST" {
				banks = append(banks, "Y")
			}
			for _, bank := range banks {
				t.Run(arch+"/"+name+"/"+bank, func(t *testing.T) {
					line := name + " " + bank + "0," + bank + "1"
					prefix := "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"
					valueProbeNeedsContext(t, arch, line)
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+line)); err != nil {
						t.Fatal("complete vector-test inputs became unsupported", err)
					}
					for _, remove := range []string{"VPXORD Z0,Z0,Z0\n", "VPXORD Z1,Z1,Z1\n"} {
						valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, remove, "", 1))
					}
					valueProbeNeedsContext(t, arch, prefix+"MOVL $1,AX\n"+name+" (AX),"+bank+"1")
				})
			}
		}
	}
}
