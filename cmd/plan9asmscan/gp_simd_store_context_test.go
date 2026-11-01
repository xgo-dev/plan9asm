package main

import "testing"

func TestGPSIMDStoreCoverageRequiresInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				valueProbeNeedsContext(t, arch, opcode+" X0,(BX)")
				valueProbeNeedsContext(t, arch, "PXOR X0,X0\nMOVL $1,BX\n"+opcode+" X0,(BX)")
			})
		}
	}
}
