package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorVariableShiftCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·vectorVariableShiftForms(SB), $0-0\n")
	for _, op := range []string{"VSSHL", "VUSHL"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
			source.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"vectorVariableShiftForms": {Name: "vectorVariableShiftForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"llvm.aarch64.neon.sshl", "llvm.aarch64.neon.ushl"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("%s variable-shift IR omitted %q:\n%s", triple, want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-variable-shift.ll", "arm64-vector-variable-shift.o", ir)
		})
	}
}

func TestTranslateARM64VectorVariableShiftRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VSSHL V0.B8, V1.B8",
		"VUSHL V0.B8, V1.B16, V2.B8",
		"VSSHL V0.D1, V1.D1, V2.D1",
		"VUSHL V0.S4, V1.S4, V2.S2",
		"VSSHL.P V0.H8, V1.H8, V2.H8",
	} {
		source := "TEXT ·badVectorVariableShift(SB), $0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badVectorVariableShift": {Name: "badVectorVariableShift", Ret: Void}}}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's VSSHL/VUSHL row", instruction)
		}
	}
}
