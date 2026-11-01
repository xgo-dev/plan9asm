package main

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCMOVCoverageRequiresDataAndPredicateInputs(t *testing.T) {
	conditions := strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS")
	for _, arch := range []string{"386", "amd64"} {
		for _, width := range []string{"W", "L", "Q"} {
			if arch == "386" && width == "Q" {
				continue
			}
			for _, condition := range conditions {
				op := "CMOV" + width + condition
				t.Run(arch+"/"+op, func(t *testing.T) {
					// The existing closed, nontrapping GP domain may leave a
					// dead named-register result unknown. Consume that result
					// through TEST/SETcc so missing data/predicate bytes cannot
					// be mistaken for initialized implementation-slot values.
					line := op + " AX,BX\nTEST" + width + " BX,BX\nSETEQ CX"
					prefix := "MOVL $3,AX\nMOVL $7,BX\nMOVL $1,DX\nCMPL DX,DX\n"
					valueProbeNeedsContext(t, arch, line)
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+line)); err != nil {
						t.Fatal("initialized complete CMOV sequence rejected", err)
					}
					for _, remove := range []string{"MOVL $3,AX\n", "MOVL $7,BX\n", "CMPL DX,DX\n"} {
						valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, remove, "", 1))
					}
					valueProbeNeedsContext(t, arch, prefix+op+" (AX),BX")
				})
			}
		}
	}
}

func TestAESCoverageRequiresActualVectorInputs(t *testing.T) {
	names := strings.Fields("AESENC AESENCLAST AESDEC AESDECLAST AESIMC AESKEYGENASSIST " +
		"VAESENC VAESENCLAST VAESDEC VAESDECLAST VAESIMC VAESKEYGENASSIST")
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range names {
			banks := []string{"X"}
			unary := strings.Contains(name, "IMC") || strings.Contains(name, "KEYGEN")
			if strings.HasPrefix(name, "V") && !unary {
				banks = append(banks, "Y", "Z")
			}
			for _, bank := range banks {
				t.Run(arch+"/"+name+"/"+bank, func(t *testing.T) {
					line := name + " " + bank + "0," + bank + "1"
					if strings.HasPrefix(name, "V") && !unary {
						line += "," + bank + "2"
					}
					if strings.Contains(name, "KEYGEN") {
						line = name + " $27," + bank + "0," + bank + "1"
					}
					destination := "X1"
					if strings.HasPrefix(name, "V") && !unary {
						destination = "X2"
					}
					// Existing dead register arithmetic may remain unknown;
					// observing it cannot borrow implementation-slot values.
					line += "\nMOVL " + destination + ",AX\nTESTL AX,AX\nSETEQ CX"
					prefix := "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"
					valueProbeNeedsContext(t, arch, line)
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, prefix+line)); err != nil {
						t.Fatal("initialized complete AES sequence rejected", err)
					}
					valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, "VPXORD Z0,Z0,Z0\n", "", 1))
					if !unary {
						valueProbeNeedsContext(t, arch, strings.Replace(prefix+line, "VPXORD Z1,Z1,Z1\n", "", 1))
					}
				})
			}
		}
	}
}
