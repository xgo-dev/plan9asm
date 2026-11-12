package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestIntegerSelfCompareCoverageNeedsNoVectorInput(t *testing.T) {
	comparisons := strings.Fields("PCMPEQB PCMPEQW PCMPEQL PCMPEQQ PCMPGTB PCMPGTW PCMPGTL PCMPGTQ")
	immediate := strings.Fields("VPCMPB VPCMPW VPCMPD VPCMPQ VPCMPUB VPCMPUW VPCMPUD VPCMPUQ")
	for _, arch := range []string{"386", "amd64"} {
		check := func(t *testing.T, row string) {
			t.Helper()
			if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
				compactProbeInstructions(t, row)); err != nil {
				t.Fatal("self-initializing integer comparison requires no incoming vector bits", arch, row, err)
			}
		}
		for _, op := range comparisons {
			t.Run(arch+"/"+op, func(t *testing.T) {
				check(t, op+" X6,X6")
				vector := "V" + strings.ReplaceAll(op, "L", "D")
				for _, bank := range []string{"X", "Y", "Z"} {
					if bank != "Z" {
						check(t, fmt.Sprintf("%s %s6,%s6,%s2", vector, bank, bank, bank))
					}
					check(t, fmt.Sprintf("%s %s6,%s6,K0", vector, bank, bank))
					if arch == "amd64" {
						masked := fmt.Sprintf("%s %s6,%s6,K1,K1", vector, bank, bank)
						valueProbeNeedsContext(t, arch, masked)
						check(t, "MOVL $85,AX\nKMOVD AX,K1\n"+masked)
					}
				}
			})
		}
		if arch == "amd64" {
			for _, op := range immediate {
				t.Run(arch+"/"+op, func(t *testing.T) {
					for _, bank := range []string{"X", "Y", "Z"} {
						check(t, fmt.Sprintf("%s $0,%s6,%s6,K0", op, bank, bank))
						valueProbeNeedsContext(t, arch, fmt.Sprintf("%s $0,%s5,%s6,K0", op, bank, bank))
					}
				})
			}
		}
	}
}

func TestLogicalCompareCoverageRequiresNativeInputContext(t *testing.T) {
	names := strings.Fields("PCMPEQB PCMPEQW PCMPEQL PCMPEQQ PCMPGTB PCMPGTW PCMPGTL PCMPGTQ " +
		"VPCMPEQB VPCMPEQW VPCMPEQD VPCMPEQQ VPCMPGTB VPCMPGTW VPCMPGTD VPCMPGTQ " +
		"ANDPS ANDPD PAND VANDPS VANDPD VPAND VPANDD VPANDQ " +
		"ANDNPS ANDNPD PANDN VANDNPS VANDNPD VPANDN VPANDND VPANDNQ " +
		"ORPS ORPD POR VORPS VORPD VPOR VPORD VPORQ " +
		"XORPS XORPD PXOR VXORPS VXORPD VPXOR VPXORD VPXORQ")
	if len(names) != 48 {
		t.Fatal("complete independent logical/compare inventory changed", len(names))
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range names {
			t.Run(arch+"/"+op, func(t *testing.T) {
				memory, registers := op+" 3(AX)(DX*2),X1", op+" X0,X1"
				if strings.HasPrefix(op, "V") {
					memory, registers = op+" 3(AX)(DX*2),X1,X2", op+" X0,X1,X2"
				}
				valueProbeNeedsContext(t, arch, memory)
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, "VZEROALL\n"+registers)); err != nil {
					t.Fatal("initialized registers became unsupported while checking native context", err)
				}
			})
		}
	}
}
