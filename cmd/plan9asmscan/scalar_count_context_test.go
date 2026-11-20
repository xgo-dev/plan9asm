package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScalarCountAndMMXStoreCoverageNeedsActualInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		check := func(t *testing.T, instruction string) {
			t.Helper()
			ins := compactProbeInstructions(t, instruction)[0]
			err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, ins)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("isolated memory form invented its pointer or MMX inputs", err)
			}
			state := &formStat{}
			classifyFormProbe(state, err)
			if state.ContextCount != 1 || state.SupportedCount != 0 || state.UnsupportedCount != 0 {
				t.Fatal("required inputs became support or an unknown instruction", state)
			}
		}
		for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
			widths := []string{"W", "L"}
			if arch == "amd64" {
				widths = append(widths, "Q")
			}
			for _, width := range widths {
				op := family + width
				t.Run(arch+"/"+op, func(t *testing.T) {
					check(t, op+" (BX),DX")
					body := "MOVL $1,AX\nMOVL $0,CX\n" + op + " AX,CX"
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, body)); err != nil {
						t.Fatal("initialized register counterpart lost its grammar", err)
					}
				})
			}
		}
		for register := 0; register < 8; register++ {
			t.Run(fmt.Sprintf("%s/MOVNTQ/M%d", arch, register), func(t *testing.T) {
				check(t, fmt.Sprintf("MOVNTQ M%d,(BX)", register))
			})
		}
	}
	// Typed native-input and object counterparts live in the complete scalar
	// count and MMX streaming root suites, not in a declaration-free probe.
}
