package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestDuplicateMoveCoverageRetainsDataMaskAndMergeInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVDDUP", "MOVSHDUP", "MOVSLDUP", "VMOVDDUP", "VMOVSHDUP", "VMOVSLDUP"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				vector := strings.HasPrefix(op, "V")
				if !vector && bank != "X" {
					continue
				}
				t.Run(arch+"/"+op+"/"+bank, func(t *testing.T) {
					instruction := op + " " + bank + "0," + bank + "2"
					valueProbeNeedsContext(t, arch, instruction)
					initialized := "VPXORQ Z0,Z0,Z0\nVPXORQ Z2,Z2,Z2\n"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, compactProbeInstructions(t, initialized+instruction)); err != nil {
						t.Fatal("initialized duplicate source disappeared from scanner", err)
					}
					valueProbeNeedsContext(t, arch, op+" (SI),"+bank+"2")
					if vector {
						masked := op + " " + bank + "0,K1," + bank + "2"
						valueProbeNeedsContext(t, arch, initialized+masked)
						valueProbeNeedsContext(t, arch, "VPXORQ Z0,Z0,Z0\nMOVL $1,AX\nKMOVD AX,K1\n"+masked)
					}
				})
			}
		}
	}
}
