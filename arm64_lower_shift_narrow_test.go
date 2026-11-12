package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorShiftNarrowCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 exposes exactly H8->B8, S4->H4, and D2->S2 for VSHRN;
	// VSHRN2 writes the same narrowed lanes into the high half. Exercise both
	// endpoints of every legal immediate interval: 1..8, 1..16, and 1..32.
	const source = `TEXT ·vectorShiftNarrowForms(SB), $0-0
	VSHRN $1, V1.H8, V0.B8
	VSHRN $8, V31.H8, V30.B8
	VSHRN $1, V2.S4, V3.H4
	VSHRN $16, V30.S4, V29.H4
	VSHRN $1, V4.D2, V5.S2
	VSHRN $32, V29.D2, V28.S2
	VSHRN2 $1, V6.H8, V7.B16
	VSHRN2 $8, V28.H8, V27.B16
	VSHRN2 $1, V8.S4, V9.H8
	VSHRN2 $16, V27.S4, V26.H8
	VSHRN2 $1, V10.D2, V11.S4
	VSHRN2 $32, V26.D2, V25.S4
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"vectorShiftNarrowForms": {Name: "vectorShiftNarrowForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"lshr <", "trunc <", "insertelement <"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s VSHRN IR omitted %q:\n%s", triple, want, ll)
			}
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-shift-narrow.ll", "arm64-vector-shift-narrow.o", ll)
	}
}

func TestTranslateARM64VectorShiftNarrowRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VSHRN $0, V0.H8, V1.B8",
		"VSHRN $9, V0.H8, V1.B8",
		"VSHRN $17, V0.S4, V1.H4",
		"VSHRN $33, V0.D2, V1.S2",
		"VSHRN V0.H8, V1.B8",
		"VSHRN $1, V0.B16, V1.B8",
		"VSHRN2 $1, V0.H8, V1.B8",
		"VSHRN.P $1, V0.H8, V1.B8",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT ·badVectorShiftNarrow(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"badVectorShiftNarrow": {Name: "badVectorShiftNarrow", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VSHRN tables", instruction)
			}
		})
	}
}
