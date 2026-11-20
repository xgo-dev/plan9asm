package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64ScalarFloatUnaryCompleteGoAssemblerForms(t *testing.T) {
	ops := []string{
		"FABSS", "FABSD", "FNEGS", "FNEGD", "FSQRTS", "FSQRTD",
		"FRINTNS", "FRINTND", "FRINTPS", "FRINTPD", "FRINTMS", "FRINTMD",
		"FRINTZS", "FRINTZD", "FRINTAS", "FRINTAD", "FRINTXS", "FRINTXD",
		"FRINTIS", "FRINTID",
	}
	var source strings.Builder
	source.WriteString("TEXT ·scalarfloatunaryforms(SB), $0-0\n")
	for _, op := range ops {
		source.WriteString("\t" + op + " F0, F31\n")
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"scalarfloatunaryforms": {Name: "scalarfloatunaryforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-scalar-float-unary.ll", "arm64-scalar-float-unary.o", ll)
		})
	}
}

func TestTranslateARM64ScalarFloatUnaryRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"FNEGD F0",
		"FNEGS F0, F1, F2",
		"FABSS R0, F1",
		"FRINTND F0, R1",
		"FRINTAS.P F0, F1",
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
			t.Fatalf("Translate accepted %q outside Go 1.27's scalar floating unary table", instruction)
		}
	}
}
