package plan9asm

import (
	"errors"
	"testing"
)

func TestProbeARM64PCRelativeAddressRequiresFunctionContext(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT probe(SB),$0-0\n\tADR target, R1\ntarget:\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := ProbeInstruction(ArchARM64, "arm64", file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("ProbeInstruction(ADR) error = %v, want ErrProbeNeedsContext", err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"probe": {Name: "probe", Ret: Void}},
	}); err != nil {
		t.Fatalf("full-function ADR translation failed: %v", err)
	}
}
