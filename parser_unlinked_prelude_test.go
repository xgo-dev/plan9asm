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
	opt := Options{
		Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"linked": {Name: "linked", Ret: I64}},
	}
	ir, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	// Compare with an independently parsed linked-only source. Its return may
	// use an SSA load rather than a folded constant; that is not a parser bug.
	const linkedSource = "TEXT linked(SB),$0-0\nMOVD $7,R0\nRET\n"
	requireARM64GoAssemblerResult(t, linkedSource, true)
	linked, err := Parse(ArchARM64, linkedSource)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Translate(linked, opt)
	if err != nil {
		t.Fatal(err)
	}
	withoutModulePath := func(ir string) string {
		var body strings.Builder
		for _, line := range strings.Split(ir, "\n") {
			// LLVM assigns each independent parse a temporary module path.
			// Ignore only that provenance, not instructions or attributes.
			if strings.HasPrefix(line, "; ModuleID = ") || strings.HasPrefix(line, "source_filename = ") {
				continue
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		return body.String()
	}
	if withoutModulePath(ir) != withoutModulePath(want) {
		t.Fatalf("unlinked prelude changed linked IR:\ngot:\n%s\nwant:\n%s", ir, want)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "unlinked-prelude.ll", "unlinked-prelude.o", ir)
}

func TestParseStillRejectsSourceWithoutTEXTOrData(t *testing.T) {
	if _, err := Parse(ArchARM64, "VST1.P [V0.D1, V1.D1], 16(R0)\n"); err == nil {
		t.Fatal("accepted a source with no linked function or data")
	}
}
