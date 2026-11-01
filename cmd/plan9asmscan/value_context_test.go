package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func valueProbeNeedsContext(t *testing.T, arch, body string) {
	t.Helper()
	err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
		compactProbeInstructions(t, body))
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Error("unknown input acquired an implementation-slot value", err)
	}
	state := &formStat{}
	classifyFormProbe(state, err)
	if state.ContextCount != 1 || state.SupportedCount != 0 || state.UnsupportedCount != 0 {
		t.Error("required source context became support or an unknown opcode", state)
	}
}

func TestMaskValueCoverageRequiresCompleteInputs(t *testing.T) {
	// Independent complete KADD/KSHIFT/KUNPCK inventory, not a production map.
	ops := strings.Fields("KADDB KADDW KADDD KADDQ " +
		"KSHIFTLB KSHIFTLW KSHIFTLD KSHIFTLQ " +
		"KSHIFTRB KSHIFTRW KSHIFTRD KSHIFTRQ KUNPCKBW KUNPCKWD KUNPCKDQ")
	if len(ops) != 15 {
		t.Fatal("complete mask-value denominator changed")
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range ops {
			t.Run(arch+"/"+op, func(t *testing.T) {
				operands := "K1,K2,K3"
				if strings.HasPrefix(op, "KSHIFT") {
					operands = "$255,K1,K3" // An oversized shift still reads K1.
				}
				instruction := op + " " + operands
				valueProbeNeedsContext(t, arch, instruction)
				prefix := "MOVL $7,AX\nKMOVD AX,K1\nKMOVD AX,K2\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+instruction)); err != nil {
					t.Error("complete initialized mask sequence rejected", err)
				}
				valueProbeNeedsContext(t, arch,
					strings.Replace(prefix+instruction, "KMOVD AX,K1\n", "", 1))
			})
		}
		for _, width := range []string{"B", "W", "D", "Q"} {
			t.Run(arch+"/KMOV"+width, func(t *testing.T) {
				instruction := "KMOV" + width + " K1,K2"
				valueProbeNeedsContext(t, arch, instruction)
				prefix := "MOVL $7,AX\nKMOVD AX,K1\n"
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, prefix+instruction)); err != nil {
					t.Error("complete initialized mask copy rejected", err)
				}
			})
		}
	}
}

func TestMaskVectorCoverageRequiresActualData(t *testing.T) {
	// Independent complete data-move family: K0 is an input, not writemasking.
	ops := strings.Fields("VPMOVM2B VPMOVM2W VPMOVM2D VPMOVM2Q VPMOVB2M VPMOVW2M VPMOVD2M VPMOVQ2M")
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range ops {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, mask := range []string{"K0", "K7"} {
					t.Run(arch+"/"+op+"/"+bank+"/"+mask, func(t *testing.T) {
						instruction := op + " " + bank + "1," + mask
						prefix := "VPXORD Z1,Z1,Z1\n"
						if strings.HasPrefix(op, "VPMOVM2") {
							instruction = op + " " + mask + "," + bank + "1"
							prefix = "MOVL $7,AX\nKMOVD AX," + mask + "\n"
						}
						valueProbeNeedsContext(t, arch, instruction)
						if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
							compactProbeInstructions(t, prefix+instruction)); err != nil {
							t.Error("initialized complete mask/vector sequence rejected", err)
						}
					})
				}
			}
		}
	}
}

func TestVectorValueCoverageRequiresCompleteInputs(t *testing.T) {
	// Register forms independently cover all 14 indexed permutes, three GFNI
	// operations and six packed bit counts. Public probe execution is Software;
	// no hardware instruction or native-memory permission is claimed here.
	ops := strings.Fields("VPERMB VPERMW VPERMI2B VPERMI2W VPERMI2D VPERMI2Q VPERMI2PS VPERMI2PD " +
		"VPERMT2B VPERMT2W VPERMT2D VPERMT2Q VPERMT2PS VPERMT2PD " +
		"VGF2P8MULB VGF2P8AFFINEQB VGF2P8AFFINEINVQB " +
		"VPOPCNTB VPOPCNTW VPOPCNTD VPOPCNTQ VPLZCNTD VPLZCNTQ")
	if len(ops) != 23 {
		t.Fatal("complete vector-value denominator changed")
	}
	for _, op := range ops {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, mode := range []string{"plain", "merge", "zero"} {
				t.Run(op+"/"+bank+"/"+mode, func(t *testing.T) {
					name, immediate, second, mask := op, "", bank+"1,", ""
					if strings.Contains(op, "AFFINE") {
						immediate = "$99,"
					}
					if strings.HasPrefix(op, "VPOPCNT") || strings.HasPrefix(op, "VPLZCNT") {
						second = ""
					}
					if mode != "plain" {
						mask = "K1,"
					}
					if mode == "zero" {
						name += ".Z"
					}
					instruction := fmt.Sprintf("%s %s%s0,%s%s%s2",
						name, immediate, bank, second, mask, bank)
					valueProbeNeedsContext(t, "amd64", instruction)
					prefix := "MOVL $7,AX\nKMOVD AX,K1\n" +
						"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, "amd64",
						compactProbeInstructions(t, prefix+instruction)); err != nil {
						t.Error("complete initialized vector sequence rejected", err)
					}
					valueProbeNeedsContext(t, "amd64",
						strings.Replace(prefix+instruction, "VPXORD Z0,Z0,Z0\n", "", 1))
				})
			}
		}
	}
}
