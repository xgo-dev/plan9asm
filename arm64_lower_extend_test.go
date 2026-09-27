package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64ScalarExtendCompleteGoAssemblerForms(t *testing.T) {
	src := `TEXT ·scalarExtendForms(SB), $0-0
	SXTB R0, R1
	SXTBW R0, R1
	SXTH R0, R1
	SXTHW R0, R1
	SXTW R0, R1
	UXTB R0, R1
	UXTBW R0, R1
	UXTH R0, R1
	UXTHW R0, R1
	UXTW R0, R1
	RET
`
	requireARM64GoAssemblerResult(t, src, true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src)
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"scalarExtendForms": {Name: "scalarExtendForms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-scalar-extend.ll", "arm64-scalar-extend.o", ll)
	}
}

func TestTranslateARM64ScalarExtendRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"SXTH $1, R1",
		"SXTH R0, 0(R1)",
		"SXTH 0(R0), R1",
		"SXTWW R0, R1",
		"UXTWW R0, R1",
		"SXTB.P R0, R1",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT ·badScalarExtend(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, src, false)
			file, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"badScalarExtend": {Name: "badScalarExtend", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's scalar extend optab", instruction)
			}
		})
	}
}
