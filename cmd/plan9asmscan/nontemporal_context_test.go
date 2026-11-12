package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestNonTemporalVectorCoverageRetainsNativeInputsAndTraps(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{
			"MOVNTO", "MOVNTDQ", "MOVNTPD", "MOVNTPS", "MOVNTDQA",
			"VMOVNTDQ", "VMOVNTPD", "VMOVNTPS", "VMOVNTDQA",
		} {
			banks := []string{"X"}
			if strings.HasPrefix(name, "V") {
				banks = []string{"X", "Y", "Z"}
			}
			for _, bank := range banks {
				t.Run(arch+"/"+name+"/"+bank, func(t *testing.T) {
					instruction := name + " " + bank + "1,(BX)"
					if strings.HasSuffix(name, "DQA") {
						instruction = name + " (BX)," + bank + "1"
					}
					err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, compactProbeInstructions(t, instruction)[0])
					if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
						t.Fatal("unbound non-temporal memory acquired native inputs", err)
					}
					state := &formStat{}
					classifyFormProbe(state, err)
					if state.ContextCount != 1 || state.SupportedCount != 0 || state.UnsupportedCount != 0 {
						t.Fatal("missing native inputs became support or unknown syntax", state)
					}
				})
			}
		}
		for _, name := range []string{"MOVNTO", "MOVNTDQ", "MOVNTPD", "MOVNTPS"} {
			if err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch,
				compactProbeInstructions(t, name+" X1,AX")[0]); err != nil {
				t.Fatal("exact legacy register #UD must precede source-input checks", arch, name, err)
			}
		}
	}
}
