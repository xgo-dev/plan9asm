package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestIFMACoverageRetainsSourceAccumulatorAndMaskInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				modes := []string{"plain"}
				if arch == "amd64" {
					modes = append(modes, "merge", "zero")
				}
				for _, mode := range modes {
					t.Run(arch+"/"+op+"/"+bank+"/"+mode, func(t *testing.T) {
						name, mask := op, ""
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							name += ".Z"
						}
						line := fmt.Sprintf("%s %s0,%s1,%s%s2\nMOVL X2,AX\nTESTL AX,AX\nSETEQ CX",
							name, bank, bank, mask, bank)
						prefix := "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
						if mode != "plain" {
							prefix += "MOVL $7,AX\nKMOVD AX,K1\n"
						}
						valueProbeNeedsContext(t, arch, line)
						if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
							compactProbeInstructions(t, prefix+line)); err != nil {
							t.Fatal("complete initialized IFMA inputs became unsupported", err)
						}
						for _, remove := range []string{"VPXORD Z0,Z0,Z0\n", "VPXORD Z1,Z1,Z1\n", "VPXORD Z2,Z2,Z2\n"} {
							valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, remove, "", 1))
						}
						if mode != "plain" {
							valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, "KMOVD AX,K1\n", "", 1))
						}
						// A numerical address does not authorize a native source,
						// even if all numerical outputs of the read are dead.
						valueProbeNeedsContext(t, arch, prefix+"MOVL $1,SI\n"+
							fmt.Sprintf("%s (SI),%s1,%s%s2", name, bank, mask, bank))
					})
				}
			}
		}
	}
}
