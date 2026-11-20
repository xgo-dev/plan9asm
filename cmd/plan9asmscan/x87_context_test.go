package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestX87CoverageProbesRequireSourceInputs(t *testing.T) {
	// The complete Go conditional family includes six aliases absent from the
	// current official syntax corpus. Never seed an isolated probe from private
	// zeroed registers, FLAGS, or an implicit default x87 control word.
	ops := strings.Fields("FCMOVCC FCMOVCS FCMOVEQ FCMOVHI FCMOVLS FCMOVB FCMOVBE " +
		"FCMOVNB FCMOVNBE FCMOVE FCMOVNE FCMOVNU FCMOVU FCMOVUN FRNDINT")
	parse := func(t *testing.T, body string) []plan9asm.Instr {
		t.Helper()
		file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT probe(SB),4,$0-0\n"+body+"\nRET\n")
		if err != nil || len(file.Funcs) != 1 {
			t.Fatal("independent probe fixture did not parse", err)
		}
		return file.Funcs[0].Instrs[1 : len(file.Funcs[0].Instrs)-1]
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range ops {
			t.Run(arch+"/"+op, func(t *testing.T) {
				instruction := op + " F1,F0"
				body := "FINIT\nFLD1\nFLD1\nMOVL $0,AX\nCMPL AX,AX\n" + instruction + "\nFINIT"
				missing := strings.Replace(body, "CMPL AX,AX\n", "", 1)
				if op == "FRNDINT" {
					instruction = op
					body = "FINIT\nFLD1\nFRNDINT\nFMOVDP F0,F0"
					missing = strings.Replace(body, "FLD1\n", "", 1)
				}
				t.Run("isolated-context", func(t *testing.T) {
					err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, parse(t, instruction)[0])
					if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
						t.Fatal("isolated opcode acquired an undefined x87 input or predicate", err)
					}
					state := &formStat{}
					classifyFormProbe(state, err)
					if state.ContextCount != 1 || state.SupportedCount != 0 || state.UnsupportedCount != 0 {
						t.Fatal("required source context was counted as supported or an unknown opcode", state)
					}
				})
				t.Run("initialized-sequence", func(t *testing.T) {
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, parse(t, body)); err != nil {
						t.Fatal("complete explicit x87 inputs and predicate did not close the probe", err)
					}
				})
				t.Run("missing-input", func(t *testing.T) {
					if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, parse(t, missing)); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
						t.Fatal("sequence without its actual input/predicate producer was accepted", err)
					}
				})
			})
		}
	}
}
