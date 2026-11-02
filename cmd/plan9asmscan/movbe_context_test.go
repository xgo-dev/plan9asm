package main

import "testing"

func TestMOVBECoverageRequiresActualMemoryAndValueInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVBEW", "MOVBEWW", "MOVBEL", "MOVBELL", "MOVBEQ", "MOVBEQQ"} {
			if arch == "386" && (op == "MOVBEQ" || op == "MOVBEQQ") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				for index, line := range []string{op + " (AX),BX", op + " BX,(AX)"} {
					valueProbeNeedsContext(t, arch, line)
					if index == 0 {
						valueProbePairedNumericAddress(t, arch, "MOVL $1,AX\nMOVL $7,BX\n"+line)
					} else {
						valueProbeNeedsContext(t, arch, "MOVL $1,AX\nMOVL $7,BX\n"+line)
					}
				}
			})
		}
	}
	// Only paired loads consume defined NUM addresses here. Special MOVBE
	// stores keep their independent role; neither route invents pointer/backing.
}
