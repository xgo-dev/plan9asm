package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorIntegerMultiplyCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·vectorIntegerMultiplyForms(SB), $0-0\n")
	for _, op := range []string{"VMUL", "VMLA", "VMLS"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4"} {
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
				"vectorIntegerMultiplyForms": {Name: "vectorIntegerMultiplyForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"mul <", "add <", "sub <"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s integer-multiply IR omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-integer-multiply.ll", "arm64-vector-integer-multiply.o", ll)
	}
}

func TestTranslateARM64VectorIntegerMultiplyRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VMUL V0.B8, V1.B8",
		"VMLA V0.B8, V1.B16, V2.B8",
		"VMLS V0.D2, V1.D2, V2.D2",
		"VMUL V0.S4, V1.S4, V2.S2",
		"VMUL.P V0.H8, V1.H8, V2.H8",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badVectorIntegerMultiply(SB), $0-0\n\t" + instruction + "\n\tRET\n"
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
					"badVectorIntegerMultiply": {Name: "badVectorIntegerMultiply", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector integer multiply forms", instruction)
			}
		})
	}
}
