package main

import (
	"errors"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestX87CompareCoverageRequiresActualSourceInputs(t *testing.T) {
	// Four official amd64enc.s forms have two distinct examples each. Neither
	// an unknown pointer nor the emitter's zeroed F0/F2/F3 cells are inputs.
	for _, source := range []string{
		"FCOMD (BX),F0", "FCOMD (R11),F0",
		"FCOMD F2,F0", "FCOMD F3,F0",
		"FCOMI F2,F0", "FCOMI F3,F0",
		"FCOMIP F2,F0", "FCOMIP F3,F0",
	} {
		t.Run(source, func(t *testing.T) {
			instruction := compactProbeInstructions(t, source)[0]
			err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, "amd64", instruction)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("isolated compare invented its pointer, floating inputs or stack depth", err)
			}
			state := &formStat{}
			classifyFormProbe(state, err)
			if state.ContextCount != 1 || state.SupportedCount != 0 || state.UnsupportedCount != 0 {
				t.Fatal("source context became supported or an unknown opcode", state)
			}
		})
	}
}
