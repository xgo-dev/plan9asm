package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScalarPrecisionCoverageRequiresActualInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"CVTSS2SD", "CVTSD2SS", "VCVTSS2SD", "VCVTSD2SS"} {
			controls := []string{""}
			if op == "VCVTSS2SD" {
				controls = append(controls, ".SAE")
			} else if op == "VCVTSD2SS" {
				controls = append(controls, ".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE")
			}
			for _, control := range controls {
				operands := "X0,X2"
				if strings.HasPrefix(op, "V") {
					operands = "X0,X1,X2"
				}
				row := op + control + " " + operands
				t.Run(arch+"/"+row, func(t *testing.T) {
					valueProbeNeedsContext(t, arch, row)
					prefix := "XORPS X0,X0\nXORPS X1,X1\nXORPS X2,X2\n"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+row)); err != nil {
						t.Fatal("complete active precision input was not supported", err)
					}
					valueProbeNeedsContext(t, arch, strings.TrimPrefix(prefix, "XORPS X0,X0\n")+row)
					if control == "" {
						native := strings.Replace(row, "X0,", "(AX),", 1)
						valueProbeNeedsContext(t, arch, prefix+"MOVL $0,AX\n"+native)
					}
				})
			}
			if arch == "amd64" && strings.HasPrefix(op, "V") {
				for _, zero := range []bool{false, true} {
					name := op
					if zero {
						name += ".Z"
					}
					row := name + " X0,X1,K1,X2"
					prefix := "MOVL $1,AX\nKMOVD AX,K1\nXORPS X0,X0\nXORPS X1,X1\nXORPS X2,X2\n"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+row)); err != nil {
						t.Fatal("complete precision mask/merge input rejected", row, err)
					}
					valueProbeNeedsContext(t, arch, strings.Replace(prefix+row, "KMOVD AX,K1\n", "", 1))
					missingOld := strings.Replace(prefix+row, "XORPS X2,X2\n", "", 1)
					if zero {
						if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
							compactProbeInstructions(t, missingOld)); err != nil {
							t.Fatal("zeroing form acquired an old scalar merge dependency", err)
						}
					} else {
						valueProbeNeedsContext(t, arch, missingOld)
					}
				}
			}
		}
	}
}
