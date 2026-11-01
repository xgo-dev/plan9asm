package main

import "testing"

func TestMOVBECoverageRequiresActualMemoryAndValueInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVBEW", "MOVBEWW", "MOVBEL", "MOVBELL", "MOVBEQ", "MOVBEQQ"} {
			if arch == "386" && (op == "MOVBEQ" || op == "MOVBEQQ") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				for _, line := range []string{op + " (AX),BX", op + " BX,(AX)"} {
					valueProbeNeedsContext(t, arch, line)
					valueProbeNeedsContext(t, arch, "MOVL $1,AX\nMOVL $7,BX\n"+line)
				}
			})
		}
	}
	// Every Go MOVBE row requires memory. Declaration-free probes cannot
	// manufacture an incoming pointer from NUM; initialized typed-entry
	// counterparts own the independent five-target, three-API object matrix.
}
