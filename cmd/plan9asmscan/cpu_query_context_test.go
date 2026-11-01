package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCPUQueryCoverageRequiresImplicitInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []string{"CPUID", "XGETBV"} {
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				for _, setup := range []string{"", "MOVL $0,AX\n", "MOVL $0,AX\nMOVB $0,CL\n"} {
					valueProbeNeedsContext(t, arch, setup+opcode)
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
