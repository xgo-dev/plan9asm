package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64PolynomialMultiplyCompleteGoAssemblerForms(t *testing.T) {
	const source = `TEXT ·polynomialMultiplyForms(SB), $0-0
	VPMULL V0.B8, V1.B8, V2.H8
	VPMULL2 V3.B16, V4.B16, V5.H8
	VPMULL V6.D1, V7.D1, V8.Q1
	VPMULL2 V9.D2, V10.D2, V11.Q1
	RET
`
	requireARM64GoAssemblerResult(t, source, true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"polynomialMultiplyForms": {Name: "polynomialMultiplyForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{
			"llvm.aarch64.neon.pmull.v8i16",
			"llvm.aarch64.neon.pmull64",
		} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s polynomial-multiply IR omitted %q:\n%s", triple, want, ll)
			}
		}
		if !strings.Contains(ll, `"target-features"="+aes"`) {
			t.Fatalf("%s polynomial-multiply function omitted +aes:\n%s", triple, ll)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-polynomial-multiply.ll", "arm64-polynomial-multiply.o", ll)
	}
}

func TestTranslateARM64PolynomialMultiplyRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPMULL V0.B16, V1.B16, V2.H8",
		"VPMULL2 V0.B8, V1.B8, V2.H8",
		"VPMULL V0.H4, V1.H4, V2.S4",
		"VPMULL V0.S2, V1.S2, V2.D2",
		"VPMULL V0.D2, V1.D2, V2.Q1",
		"VPMULL V0.D1, V1.D1, V2.D2",
		"VPMULL.P V0.B8, V1.B8, V2.H8",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badPolynomialMultiply(SB), $0-0\n\t" + instruction + "\n\tRET\n"
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
					"badPolynomialMultiply": {Name: "badPolynomialMultiply", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go's VPMULL/VPMULL2 optab", instruction)
			}
		})
	}
}
