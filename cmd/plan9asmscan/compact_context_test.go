package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

var compactProbeOpcodes = strings.Fields("VCOMPRESSPS VCOMPRESSPD VPCOMPRESSB VPCOMPRESSW VPCOMPRESSD VPCOMPRESSQ " +
	"VEXPANDPS VEXPANDPD VPEXPANDB VPEXPANDW VPEXPANDD VPEXPANDQ")

func compactProbeInstructions(t *testing.T, body string) []plan9asm.Instr {
	t.Helper()
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT probe(SB),4,$0-0\n"+body+"\nRET\n")
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("independent compact probe fixture did not parse", err)
	}
	return file.Funcs[0].Instrs[1 : len(file.Funcs[0].Instrs)-1]
}

func compactProbeInstruction(op, bank, mode string) string {
	switch mode {
	case "unmasked":
		return fmt.Sprintf("%s %s0,%s1", op, bank, bank)
	case "merge":
		return fmt.Sprintf("%s %s0,K1,%s1", op, bank, bank)
	case "zero":
		return fmt.Sprintf("%s.Z %s0,K1,%s1", op, bank, bank)
	default:
		panic("unknown independent probe mode")
	}
}

func TestCompactCoverageProbesRequireSourceInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range compactProbeOpcodes {
			for _, bank := range []string{"X", "Y", "Z"} {
				forms := []string{
					compactProbeInstruction(op, bank, "unmasked"),
					compactProbeInstruction(op, bank, "merge"),
					compactProbeInstruction(op, bank, "zero"),
					fmt.Sprintf("%s %s0,K1,8(AX)", op, bank),
				}
				if strings.Contains(op, "EXPAND") {
					forms[3] = fmt.Sprintf("%s 8(AX),K1,%s1", op, bank)
				}
				for _, form := range forms {
					t.Run(arch+"/"+form, func(t *testing.T) {
						instruction := compactProbeInstructions(t, form)[0]
						err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, instruction)
						if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
							t.Error("isolated compact opcode acquired unknown source, mask, merge or memory inputs", err)
						}
						state := &formStat{}
						classifyFormProbe(state, err)
						if state.ContextCount != 1 || state.SupportedCount != 0 || state.UnsupportedCount != 0 {
							t.Error("missing inputs were counted as supported or an unknown opcode", state)
						}
					})
				}
			}
		}
	}
}

func TestCompactCoverageSequencesKeepCompleteInputRequirements(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range compactProbeOpcodes {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, mode := range []string{"unmasked", "merge", "zero"} {
					t.Run(arch+"/"+op+"/"+bank+"/"+mode, func(t *testing.T) {
						body := "MOVL $7,AX\nKMOVD AX,K1\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n" +
							compactProbeInstruction(op, bank, mode)
						probe := func(source string) error {
							return plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, compactProbeInstructions(t, source))
						}
						if err := probe(body); err != nil {
							t.Error("complete explicit compact inputs were rejected", err)
						}
						if err := probe(strings.Replace(body, "VPXORD Z0,Z0,Z0\n", "", 1)); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
							t.Error("missing source vector became initialized", err)
						}
						if mode != "unmasked" {
							if err := probe(strings.Replace(body, "KMOVD AX,K1\n", "", 1)); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
								t.Error("unknown mask became a complete byte dependency", err)
							}
						}
						err := probe(strings.Replace(body, "VPXORD Z1,Z1,Z1\n", "", 1))
						if mode == "merge" && !errors.Is(err, plan9asm.ErrProbeNeedsContext) || mode != "merge" && err != nil {
							t.Error("old destination requirements did not match merge versus overwrite", err)
						}
					})
				}
			}
		}
	}
}
