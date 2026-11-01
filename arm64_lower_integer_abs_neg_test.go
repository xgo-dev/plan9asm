package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorIntegerAbsNegCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·vectorIntegerAbsNegForms(SB), $0-0\n")
	for _, op := range []string{"VABS", "VNEG", "VSQABS", "VSQNEG"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
			source.WriteString("\t" + op + " V0." + arrangement + ", V31." + arrangement + "\n")
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
				"vectorIntegerAbsNegForms": {Name: "vectorIntegerAbsNegForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"sub <", "icmp slt <", "icmp eq <", "select <"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s integer abs/neg IR omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-integer-abs-neg.ll", "arm64-vector-integer-abs-neg.o", ll)
	}
}

func TestTranslateARM64VectorIntegerAbsNegRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VABS V0.B8",
		"VNEG V0.B8, V1.B16",
		"VSQABS V0.D1, V1.D1",
		"VSQNEG V0.B16, V1.B16, V2.B16",
		"VABS.P V0.S4, V1.S4",
		"VABS F0, F1",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badVectorIntegerAbsNeg(SB), $0-0\n\t" + instruction + "\n\tRET\n"
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
					"badVectorIntegerAbsNeg": {Name: "badVectorIntegerAbsNeg", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector integer abs/neg forms", instruction)
			}
		})
	}
}
