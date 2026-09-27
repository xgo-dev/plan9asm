package plan9asm

import (
	"strings"
	"testing"
)

func TestParseIgnoresGoUnlinkedInstructionsBeforeFirstTEXT(t *testing.T) {
	const source = `
	VST1.P [V0.D1, V1.D1, V2.D1, V3.D1], 32(R0)
	RET
TEXT linked(SB),$0-0
	MOVD $7, R0
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 3 || file.Funcs[0].Sym != "linked" {
		t.Fatalf("prelude attached to a linked function: %+v", file.Funcs)
	}
	if len(file.UnlinkedPrelude) != 2 || !strings.HasPrefix(file.UnlinkedPrelude[0], "VST1.P") || file.UnlinkedPrelude[1] != "RET" {
		t.Fatalf("unlinked prelude not retained as evidence: %#v", file.UnlinkedPrelude)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"linked": {Name: "linked", Ret: I64}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "ret i64 7") {
		t.Fatalf("linked function changed by Go's unlinked prelude:\n%s", ir)
	}
}

func TestParseStillRejectsSourceWithoutTEXTOrData(t *testing.T) {
	if _, err := Parse(ArchARM64, "VST1.P [V0.D1, V1.D1], 16(R0)\n"); err == nil {
		t.Fatal("accepted a source with no linked function or data")
	}
}
