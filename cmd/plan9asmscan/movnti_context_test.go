package main

import (
	"errors"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestMOVNTICoverageRetainsValueAddressAndNativeStorage(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"MOVNTIL", "MOVNTIQ"} {
			if arch == "386" && name == "MOVNTIQ" {
				continue
			}
			t.Run(arch+"/"+name, func(t *testing.T) {
				for _, line := range []string{
					name + " AX,(BX)",
					"MOVL $1,AX\nMOVL $32,BX\n" + name + " AX,(BX)",
					"MOVL $1,AX\n" + name + " AX,ret+0(FP)",
					"MOVL $1,AX\n" + name + " AX,tmp-8(SP)",
				} {
					valueProbeNeedsContext(t, arch, line)
				}
				instruction := compactProbeInstructions(t, name+" AX,BX")[0]
				if err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, instruction); err != nil {
					t.Fatal("Go register-destination #UD consumed unknown data", err)
				}
				memory := compactProbeInstructions(t, name+" AX,(BX)")[0]
				err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, memory)
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatal("unbound MOVNTI memory became an unsupported form or a false pass", err)
				}
				state := &formStat{}
				classifyFormProbe(state, err)
				if state.ContextCount != 1 || state.SupportedCount != 0 || state.UnsupportedCount != 0 {
					t.Fatal("unbound MOVNTI lost its explicit context classification", state)
				}
			})
		}
	}
}
