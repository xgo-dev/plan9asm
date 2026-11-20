package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCPUQueryCoverageRequiresImplicitInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []string{"CPUID", "XGETBV"} {
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				for _, row := range []struct {
					setup    string
					rootLeaf bool
				}{
					{"", false},
					{"MOVL $0,AX\n", true},
					{"MOVL $0,AX\nMOVB $0,CL\n", true},
					{"MOVL $0x80000000,AX\n", true},
					{"MOVL $1,AX\n", false},
					{"MOVL $7,AX\n", false},
					{"MOVL $7,AX\nMOVB $0,CL\n", false},
				} {
					if opcode != "CPUID" || !row.rootLeaf {
						valueProbeNeedsContext(t, arch, row.setup+opcode)
						continue
					}
					err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
						compactProbeInstructions(t, row.setup+opcode))
					state := &formStat{}
					classifyFormProbe(state, err)
					if err != nil || state.SupportedCount != 1 || state.ContextCount != 0 || state.UnsupportedCount != 0 {
						t.Error("maximum CPUID leaf incorrectly requires an incoming ECX selector", err, state)
					}
				}
				setup := "MOVL $0,CX\n"
				if opcode == "CPUID" {
					valueProbeNeedsContext(t, arch, setup+opcode)
					setup += "MOVL $0,AX\n"
				}
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch,
					compactProbeInstructions(t, setup+opcode)); err != nil {
					t.Error("complete low-dword query inputs lost their supported sequence", err)
				}
			})
		}
	}
}
