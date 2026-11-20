package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorIntegerMinMaxCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·vectorintegerminmaxforms(SB), $0-0\n")
	for _, op := range []string{"VSMAX", "VSMIN", "VUMAX", "VUMIN", "VSMAXP", "VSMINP", "VUMAXP", "VUMINP"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4"} {
			source.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs:         map[string]FuncSig{"vectorintegerminmaxforms": {Name: "vectorintegerminmaxforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-integer-minmax.ll", "arm64-vector-integer-minmax.o", ll)
		})
	}
}

func TestTranslateARM64VectorIntegerMinMaxRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VUMAX V0.D2, V1.D2, V2.D2",
		"VSMIN V0.S2, V1.S4, V2.S2",
		"VUMAXP V0.H8, V1.H8",
		"VSMAX.P V0.B16, V1.B16, V2.B16",
		"VUMIN R0, V1.S4, V2.S4",
	} {
		source := "TEXT ·bad(SB), $0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's vector integer min/max table", instruction)
		}
	}
}
