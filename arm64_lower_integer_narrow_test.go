package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorIntegerNarrowCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·vectorIntegerNarrowForms(SB), $0-0\n")
	for _, op := range []string{"VXTN", "VSQXTN", "VSQXTUN", "VUQXTN"} {
		source.WriteString("\t" + op + " V0.H8, V1.B8\n")
		source.WriteString("\t" + op + " V2.S4, V3.H4\n")
		source.WriteString("\t" + op + " V4.D2, V5.S2\n")
		source.WriteString("\t" + op + "2 V6.H8, V7.B16\n")
		source.WriteString("\t" + op + "2 V8.S4, V9.H8\n")
		source.WriteString("\t" + op + "2 V10.D2, V11.S4\n")
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
				"vectorIntegerNarrowForms": {Name: "vectorIntegerNarrowForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"trunc <", "icmp slt <", "icmp sgt <", "icmp ugt <", "insertelement <"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s integer narrow IR omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-integer-narrow.ll", "arm64-vector-integer-narrow.o", ll)
	}
}

func TestTranslateARM64VectorIntegerNarrowRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VXTN V0.B8, V1.B8",
		"VXTN2 V0.H8, V1.B8",
		"VSQXTN V0.H8, V1.B16",
		"VSQXTUN2 V0.S4, V1.S4",
		"VUQXTN V0.D2, V1.H4",
		"VUQXTN.P V0.H8, V1.B8",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badVectorIntegerNarrow(SB), $0-0\n\t" + instruction + "\n\tRET\n"
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
					"badVectorIntegerNarrow": {Name: "badVectorIntegerNarrow", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector integer narrowing forms", instruction)
			}
		})
	}
}
