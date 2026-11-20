package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64UnsignedWideningAddCompleteGoAssemblerForms(t *testing.T) {
	type form struct{ narrow, wide string }
	var source strings.Builder
	source.WriteString("TEXT ·unsignedWideningAddForms(SB), $0-0\n")
	for _, family := range []struct {
		op    string
		forms []form
	}{
		{op: "VUADDW", forms: []form{{"B8", "H8"}, {"H4", "S4"}, {"S2", "D2"}}},
		{op: "VUADDW2", forms: []form{{"B16", "H8"}, {"H8", "S4"}, {"S4", "D2"}}},
	} {
		for _, form := range family.forms {
			fmt.Fprintf(&source, "\t%s V0.%s, V1.%s, V2.%s\n", family.op, form.narrow, form.wide, form.wide)
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
				"unsignedWideningAddForms": {Name: "unsignedWideningAddForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		if got := strings.Count(ll, " = zext <"); got != 6 {
			t.Fatalf("%s emitted %d widening extensions, want 6:\n%s", triple, got, ll)
		}
		if got := strings.Count(ll, " = add <"); got != 6 {
			t.Fatalf("%s emitted %d vector additions, want 6:\n%s", triple, got, ll)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-unsigned-widening-add.ll", "arm64-unsigned-widening-add.o", ll)
	}
}

func TestTranslateARM64UnsignedWideningAddRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VUADDW V0.B16, V1.H8, V2.H8",
		"VUADDW2 V0.B8, V1.H8, V2.H8",
		"VUADDW V0.B8, V1.H8, V2.S4",
		"VUADDW V0.H4, V1.D2, V2.D2",
		"VUADDW V0.B8, V1.H8",
		"VUADDW.P V0.B8, V1.H8, V2.H8",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·badUnsignedWideningAdd(SB), $0-0\n\t" + instruction + "\n\tRET\n"
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
					"badUnsignedWideningAdd": {Name: "badUnsignedWideningAdd", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VUADDW family", instruction)
			}
		})
	}
}
