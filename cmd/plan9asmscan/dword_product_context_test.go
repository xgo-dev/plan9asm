package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestDwordProductCoverageRequiresActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"PMULDQ", "PMULULQ", "VPMULDQ", "VPMULUDQ"} {
			banks := []string{"X"}
			if strings.HasPrefix(name, "V") {
				banks = append(banks, "Y", "Z")
			}
			for _, bank := range banks {
				instruction := name + " " + bank + "0," + bank + "1"
				if strings.HasPrefix(name, "V") {
					instruction += "," + bank + "2"
				}
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					valueProbeNeedsContext(t, arch, instruction)
					prefix := "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+instruction)); err != nil {
						t.Fatal("complete initialized product sequence rejected", err)
					}
					valueProbeNeedsContext(t, arch, strings.Replace(prefix+instruction, "VPXORD Z0,Z0,Z0\n", "", 1))
				})
			}
		}
	}
}
