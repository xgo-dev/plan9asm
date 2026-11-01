package main

import (
	"fmt"
	"testing"
)

func TestExplicitMaskMoveCoverageKeepsNativeInputsAndMemoryContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"VMASKMOVPS", "VMASKMOVPD", "VPMASKMOVD", "VPMASKMOVQ"} {
			for _, bank := range []string{"X", "Y"} {
				for _, row := range []string{
					fmt.Sprintf("%s (AX),%s1,%s0", op, bank, bank),
					fmt.Sprintf("%s %s0,%s1,(AX)", op, bank, bank),
				} {
					t.Run(arch+"/"+row, func(t *testing.T) {
						valueProbeNeedsContext(t, arch, row)
						// Even explicit numerical data/sign bytes and a zero
						// address are not an incoming native pointer or backing.
						valueProbeNeedsContext(t, arch,
							"VXORPS X0,X0,X0\nVXORPS X1,X1,X1\nMOVL $0,AX\n"+row)
					})
				}
			}
		}
	}
}
