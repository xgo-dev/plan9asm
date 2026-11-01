package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestProbe386LegacyImmediateJumpRequiresLayoutContext(t *testing.T) {
	const source = "TEXT legacyJump(SB),$0-0\n\tJMP $4\n"
	requireX86GoAssemblerResult(t, "386", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	instruction := file.Funcs[0].Instrs[1]
	err = ProbeInstruction(ArchAMD64, "386", instruction)
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("ProbeInstruction(JMP $4) error = %v, want ErrProbeNeedsContext", err)
	}
	if !strings.Contains(err.Error(), "JMP $4") || !strings.Contains(err.Error(), "layout") {
		t.Fatalf("context error does not explain the legacy relocation: %v", err)
	}
}
