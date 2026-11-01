package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorHalvingAddCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·vectorHalvingAddForms(SB), $0-0\n")
	for _, op := range []string{"VSHADD", "VSRHADD", "VUHADD", "VURHADD"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
			source.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"vectorHalvingAddForms": {Name: "vectorHalvingAddForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"sext <", "zext <", "ashr <", "lshr <", "trunc <"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s halving-add IR omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-halving-add.ll", "arm64-vector-halving-add.o", ll)
	}
}

func TestTranslateARM64VectorHalvingAddRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VSHADD V0.B8, V1.B8",
		"VSRHADD V0.B8, V1.B16, V2.B8",
		"VUHADD V0.D1, V1.D1, V2.D1",
		"VURHADD V0.S4, V1.S4, V2.S2",
		"VURHADD.P V0.H8, V1.H8, V2.H8",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badVectorHalvingAdd(SB), $0-0\n\t" + instruction + "\n\tRET\n"
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
					"badVectorHalvingAdd": {Name: "badVectorHalvingAdd", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector halving-add forms", instruction)
			}
		})
	}
}
