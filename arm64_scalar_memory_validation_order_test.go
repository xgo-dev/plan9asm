package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64ScalarMemoryGrammarPreservesFloatingClassDiagnostic(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		for _, literal := range []string{"0.0", "-0.0", "1.5", "-1.5"} {
			for _, shape := range []struct{ suffix, memory string }{
				{memory: "8(R0)"},
				{memory: "ret+8(FP)"},
				{memory: "storage(SB)"},
				{suffix: ".P", memory: "8(R0)"},
				{suffix: ".W", memory: "8(R0)"},
			} {
				instruction := fmt.Sprintf("%s%s $%s,%s", op, shape.suffix, literal, shape.memory)
				t.Run(instruction, func(t *testing.T) {
					file, err := Parse(ArchARM64, "TEXT invalid(SB),516,$0-16\n"+instruction+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					_, handled, err := parseARM64ScalarMemoryForm(Op(op), file.Funcs[0].Instrs[1])
					if !handled || err == nil || !strings.Contains(err.Error(), "floating immediate") {
						t.Fatalf("typed memory grammar = (%v, %v), want the distinct floating class refusal", handled, err)
					}
				})
			}
		}
	}
}

func TestARM64ScalarMemoryNonzeroImmediateStoreRejectedLikeGo(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		for _, shape := range []struct{ suffix, memory string }{
			{memory: "8(R0)"},
			{memory: "ret+8(FP)"},
			{memory: "storage(SB)"},
			{suffix: ".P", memory: "8(R0)"},
			{suffix: ".W", memory: "8(R0)"},
		} {
			instruction := fmt.Sprintf("%s%s $21,%s", op, shape.suffix, shape.memory)
			t.Run(instruction, func(t *testing.T) {
				source := "GLOBL storage(SB),16,$8\nTEXT invalid(SB),516,$0-16\n" + instruction + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, handled, err := parseARM64ScalarMemoryForm(Op(op), file.Funcs[0].Instrs[1])
				if !handled || err == nil {
					t.Fatalf("typed memory grammar = (%v, %v), accepted Go-invalid immediate store", handled, err)
				}
			})
		}
	}
}
