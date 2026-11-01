package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestFloatingCompareCoverageNeedsActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range strings.Fields("CMPPS CMPPD CMPSS CMPSD VCMPPS VCMPPD VCMPSS VCMPSD") {
			if arch == "386" && strings.HasPrefix(op, "V") {
				continue // Named V comparisons are absent from Go's 386 frontend.
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				row := op + " X0,X1,$0"
				if strings.HasPrefix(op, "V") {
					row = op + " $255,X0,X1,X2"
				}
				valueProbeNeedsContext(t, arch, row)
				prefix := "PXOR X0,X0\nPXOR X1,X1\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+row)); err != nil {
					t.Fatal("initialized comparison lost its complete input grammar", err)
				}
			})
		}
	}
}

func TestBroadcastCoverageNeedsActualInputs(t *testing.T) {
	// Independent complete family, not the translator's instruction map.
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range strings.Fields("VPBROADCASTB VPBROADCASTW VPBROADCASTD VPBROADCASTQ " +
			"VBROADCASTSS VBROADCASTSD VBROADCASTF128 VBROADCASTI128 " +
			"VBROADCASTF32X2 VBROADCASTI32X2 VBROADCASTF32X4 VBROADCASTF64X2 " +
			"VBROADCASTI32X4 VBROADCASTI64X2 VBROADCASTF32X8 VBROADCASTF64X4 " +
			"VBROADCASTI32X8 VBROADCASTI64X4 VPBROADCASTMB2Q VPBROADCASTMW2D") {
			t.Run(arch+"/"+op, func(t *testing.T) {
				input, bank, prefix := "(AX)", "Z", ""
				switch op {
				case "VPBROADCASTMB2Q", "VPBROADCASTMW2D":
					input, prefix = "K0", "MOVL $7,AX\nKMOVD AX,K0\n"
				case "VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ",
					"VBROADCASTSS", "VBROADCASTSD", "VBROADCASTF32X2", "VBROADCASTI32X2":
					input, prefix = "X1", "PXOR X1,X1\n"
				case "VBROADCASTF128", "VBROADCASTI128":
					bank = "Y"
				}
				row := fmt.Sprintf("%s %s,%s2", op, input, bank)
				valueProbeNeedsContext(t, arch, row)
				if prefix != "" {
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+row)); err != nil {
						t.Fatal("initialized register broadcast became unsupported", err)
					}
				}
			})
		}
	}
}
