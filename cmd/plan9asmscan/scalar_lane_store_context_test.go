package main

import "testing"

func TestScalarLaneStoreCoverageRequiresSelectedInputsAndAddress(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []string{"PEXTRB", "PEXTRW", "PEXTRD", "PEXTRQ", "VPEXTRB", "VPEXTRW", "VPEXTRD", "VPEXTRQ", "EXTRACTPS", "VEXTRACTPS"} {
			if arch == "386" && opcode == "PEXTRQ" {
				continue // Its actual Go rejection is owned by the independent table oracle.
			}
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				valueProbeNeedsContext(t, arch, opcode+" $1,X1,(BX)")
				// Source initialization alone does not supply a native address.
				valueProbeNeedsContext(t, arch, "PXOR X1,X1\n"+opcode+" $1,X1,(BX)")
			})
		}
	}
}
