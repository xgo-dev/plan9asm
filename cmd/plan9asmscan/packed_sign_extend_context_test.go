package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestPackedSignExtendCoverageRetainsActualInputsAndVoidE5Reads(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, ratio := range []struct {
			suffix string
			twice  bool
		}{{"BW", true}, {"BD", false}, {"BQ", false}, {"WD", true}, {"WQ", false}, {"DQ", true}} {
			for _, vector := range []bool{false, true} {
				for _, bank := range []string{"X", "Y", "Z"} {
					if !vector && bank != "X" {
						continue
					}
					input := "X0"
					if bank == "Z" && ratio.twice {
						input = "Y0"
					}
					for _, mode := range []string{"plain", "merge", "zero"} {
						if !vector && mode != "plain" {
							continue
						}
						op, mask := "PMOVSX"+ratio.suffix, ""
						if vector {
							op = "V" + op
						}
						if mode != "plain" {
							mask = "K1,"
							if mode == "zero" {
								op += ".Z"
							}
						}
						row := fmt.Sprintf("%s %s,%s%s1", op, input, mask, bank)
						t.Run(arch+"/"+row, func(t *testing.T) {
							// Unlike a dead copy, TEST consumes actual result bits and
							// SETEQ consumes the resulting ZF. A bare/no-input value
							// therefore cannot become numerical implementation storage.
							observe := "\nMOVL X1,AX\nTESTL AX,AX\nSETEQ CX"
							valueProbeNeedsContext(t, arch, row+observe)
							prefix := "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nMOVL $-1,AX\nKMOVD AX,K1\n"
							probe := func(body string) error {
								return plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, compactProbeInstructions(t, body))
							}
							if err := probe(prefix + row + observe); err != nil {
								t.Fatal("complete initialized signed input/mask sequence rejected", err)
							}
							valueProbeNeedsContext(t, arch, strings.Replace(prefix+row+observe, "VPXORD Z0,Z0,Z0\n", "", 1))
							if mode != "plain" {
								valueProbeNeedsContext(t, arch, strings.Replace(prefix+row+observe, "KMOVD AX,K1\n", "", 1))
							}
							withoutOld := strings.Replace(prefix+row+observe, "VPXORD Z1,Z1,Z1\n", "", 1)
							if mode == "merge" {
								valueProbeNeedsContext(t, arch, withoutOld)
							} else if err := probe(withoutOld); err != nil {
								t.Fatal("non-merge widening invented an old-destination dependency", err)
							}
							// E5 masking may suppress actual accesses; it does not make
							// numeric zero a pointer or grant this declaration-free probe
							// native memory. Keep this rejection even for a dead result.
							memory := strings.Replace(row, input+",", "(AX),", 1)
							valueProbeNeedsContext(t, arch, memory)
							valueProbeNeedsContext(t, arch, prefix+"MOVL $0,AX\n"+memory)
							if mode != "plain" {
								valueProbeNeedsContext(t, arch, prefix+"MOVL $0,AX\nKMOVD AX,K1\n"+memory)
							}
						})
					}
				}
			}
		}
	}
}
