package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestQwordLookupCoverageRequiresActualInputsAndMaskRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VPMULTISHIFTQB", "VPSHUFBITQMB"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				modes := []string{"plain"}
				if arch == "amd64" {
					modes = append(modes, "merge")
					if op == "VPMULTISHIFTQB" {
						modes = append(modes, "zero")
					}
				}
				for _, mode := range modes {
					t.Run(arch+"/"+op+"/"+bank+"/"+mode, func(t *testing.T) {
						name, mask, destination := op, "", bank+"2"
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							name += ".Z"
						}
						if op == "VPSHUFBITQMB" {
							destination = "K3"
						}
						line := name + " " + bank + "0," + bank + "1," + mask + destination
						prefix := "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\nMOVL $7,AX\nKMOVD AX,K1\n"
						valueProbeNeedsContext(t, arch, line)
						if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
							compactProbeInstructions(t, prefix+line)); err != nil {
							t.Fatal("complete qword lookup inputs became unsupported", err)
						}
						for _, remove := range []string{"VPXORD Z0,Z0,Z0\n", "VPXORD Z1,Z1,Z1\n"} {
							valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, remove, "", 1))
						}
						if mode != "plain" {
							valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, "KMOVD AX,K1\n", "", 1))
						}
						if op == "VPMULTISHIFTQB" && mode == "merge" {
							valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, "VPXORD Z2,Z2,Z2\n", "", 1))
						}
						valueProbeNeedsContext(t, arch, prefix+"MOVL $1,SI\n"+
							name+" (SI),"+bank+"1,"+mask+destination)
					})
				}
			}
		}
	}
}
