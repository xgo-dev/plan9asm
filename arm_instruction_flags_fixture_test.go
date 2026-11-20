package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestARMSingleInstructionProbeSuppliesExplicitFlagsFixture(t *testing.T) {
	var objectSource strings.Builder
	objectSource.WriteString("TEXT fixture(SB),4,$0\n")
	for _, op := range []string{"ADC", "SBC", "RSC"} {
		for _, source := range []string{"R0", "$255", "R0<<28", "R0>>28", "R0->28", "R0@>28", "R0<<R1", "R0>>R1", "R0->R1", "R0@>R1"} {
			for _, destination := range []string{"R2", "R2,R3"} {
				instruction := op + " " + source + "," + destination
				file, err := Parse(ArchARM, "TEXT fixture(SB),$0\n "+instruction+"\n RET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				if err := ProbeInstruction(ArchARM, "arm", ins); err != nil {
					t.Errorf("single-form fixture supplies explicit source carry for %s: %v", instruction, err)
				}
				if err := ProbeInstructionSequence(ArchARM, "arm", []Instr{ins}); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("a source sequence must not invent entry carry for %s: %v", instruction, err)
				}
				objectSource.WriteString(" CMP R0,R0\n " + instruction + "\n")
			}
		}
	}
	objectSource.WriteString(" RET\n")
	requireARMGoAssemblerResult(t, objectSource.String(), true)

	conditional, err := Parse(ArchARM, "TEXT fixture(SB),$0\n MOVW.EQ $1,R2\n RET\n")
	if err != nil {
		t.Fatal(err)
	}
	ins := conditional.Funcs[0].Instrs[1]
	if err := ProbeInstruction(ArchARM, "arm", ins); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unrelated predicate-only form retains its context boundary: %v", err)
	}
	if err := ProbeInstructionSequence(ArchARM, "arm", []Instr{ins}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("full sequence cannot invent incoming predicate: %v", err)
	}
}

func TestARMFlagsProbeFixtureDoesNotInventNativeCPSR(t *testing.T) {
	for _, instruction := range []string{"MOVW CPSR,R0", "MOVW.EQ CPSR,R0"} {
		file, err := Parse(ArchARM, "TEXT fixture(SB),$0\n "+instruction+"\n RET\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := ProbeInstruction(ArchARM, "arm", file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("native CPSR source cannot be replaced by synthetic flags: %s: %v", instruction, err)
		}
	}
}
