package plan9asm

import (
	"math"
	"testing"
)

func TestGoFloatLiteralUnaryAssemblyTokens(t *testing.T) {
	for _, row := range []struct {
		text string
		bits uint64
	}{
		{"--0.0", 0}, {"++0.0", 0}, {"+-0.0", 1 << 63},
		{"-+(0.0)", 1 << 63}, {"(--1.0)", 0x3ff0000000000000},
		{"++(-1.0)", 0xbff0000000000000}, {"-(+(-0x1p-4))", 0x3fb0000000000000},
	} {
		operand, err := parseOperand("$" + row.text)
		if err != nil || operand.Kind != OpImm || !operand.ImmIsFloat || operand.ImmRaw != "" || uint64(operand.Imm) != row.bits {
			t.Fatalf("assembly FLOAT tokens %s: %+v / %v", row.text, operand, err)
		}
		value, valid := parseGoFloatLiteral(row.text)
		if !valid || math.Float64bits(value) != row.bits {
			t.Fatalf("typed FLOAT identity mismatch: %s", row.text)
		}
	}
}

func TestGoFloatLiteralDoesNotAuthorizeOtherConstantClasses(t *testing.T) {
	for _, text := range []string{"1", "--1", "0x3ff0000000000000", "name", "1.0+2.0", "(1.0/2.0)", "(1.0", "1.0)", "NaN", "Inf", "1e999"} {
		if _, valid := parseGoFloatLiteral(text); valid {
			t.Fatalf("nonliteral acquired assembly FLOAT identity: %s", text)
		}
	}
	for _, text := range []string{"1", "0", "0x3ff0000000000000", "(1+2)"} {
		operand, err := parseOperand("$" + text)
		if err != nil || operand.ImmIsFloat || operand.ImmRaw != "" {
			t.Fatalf("integer constant changed class: %s / %+v / %v", text, operand, err)
		}
	}
	for _, arch := range []Arch{ArchARM, ArchARM64, ArchWASM, ArchAMD64} {
		file, err := Parse(arch, "TEXT f(SB),4,$0-0\nMOVD $--1.0,R0\nRET\n")
		if err != nil || !file.Funcs[0].Instrs[1].Args[0].ImmIsFloat {
			t.Fatalf("shared frontend lost FLOAT class on %s: %v", arch, err)
		}
		// Parsing is not an opcode, native register or source-frame grant.
		// Existing architecture validators still own acceptance and effects.
		for _, text := range []string{"--1", "--(1.0+2.0)", "--(1.0/2.0)", "NaN", "Inf", "1e999", "(1.0", "1.0)"} {
			file, err := Parse(arch, "TEXT f(SB),4,$0-0\nMOVD $"+text+",R0\nRET\n")
			if err == nil && file.Funcs[0].Instrs[1].Args[0].ImmIsFloat {
				t.Fatalf("invalid unary FLOAT grammar acquired a resolved FLOAT on %s: %s", arch, text)
			}
		}
	}
}
