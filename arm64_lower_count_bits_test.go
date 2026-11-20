package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorCountBitsCompleteGoAssemblerForms(t *testing.T) {
	source := `TEXT ·vectorCountBitsForms(SB), $0-0
	VCNT V0.B8, V1.B8
	VCNT V0.B16, V1.B16
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
				"vectorCountBitsForms": {Name: "vectorCountBitsForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-count-bits.ll", "arm64-vector-count-bits.o", ll)
	}
}

func TestTranslateARM64VectorCountBitsRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VCNT V0.H4, V1.H4",
		"VCNT V0.B8, V1.B16",
		"VCNT V0.B16, V1.B8",
		"VCNT V0.B8, V1.B8, V2.B8",
		"VCNT.P V0.B16, V1.B16",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badVectorCountBits(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"badVectorCountBits": {Name: "badVectorCountBits", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VCNT forms", instruction)
			}
		})
	}
}
