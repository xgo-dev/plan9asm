package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorIntegerMinMaxAcrossCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·vectorIntegerMinMaxAcrossForms(SB), $0-0\n")
	for _, op := range []string{"VSMAXV", "VSMINV", "VUMAXV", "VUMINV"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S4"} {
			source.WriteString("\t" + op + " V0." + arrangement + ", V31\n")
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
				"vectorIntegerMinMaxAcrossForms": {Name: "vectorIntegerMinMaxAcrossForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"icmp sgt i", "icmp slt i", "icmp ugt i", "icmp ult i", "select i1"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s integer min/max-across IR omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-integer-minmax-across.ll", "arm64-vector-integer-minmax-across.o", ll)
	}
}

func TestTranslateARM64VectorIntegerMinMaxAcrossRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VSMAXV V0.B8",
		"VSMINV V0.S2, V1",
		"VUMAXV V0.D2, V1",
		"VUMINV V0.H8, V1.H8",
		"VUMINV.P V0.S4, V1",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badVectorIntegerMinMaxAcross(SB), $0-0\n\t" + instruction + "\n\tRET\n"
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
					"badVectorIntegerMinMaxAcross": {Name: "badVectorIntegerMinMaxAcross", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector integer min/max-across forms", instruction)
			}
		})
	}
}
