package asm

import (
	"strings"
	"testing"
)

func TestParseARMSymbolicImmediateExpr(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·f(SB),NOSPLIT,$0-0
	MOVW $(16 + callbackArgs__size), R0
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := file.Funcs[0].Instrs[1].Args[0]; got.Kind != OpImm {
		t.Fatalf("unexpected operand kind: %#v", got)
	} else if got.ImmRaw == "" {
		t.Fatalf("symbolic immediate should be marked unresolved: %#v", got)
	}
}

func TestParseRegisterRelativeAddressExpression(t *testing.T) {
	for _, tc := range []struct {
		text string
		base Reg
		off  int64
	}{
		{text: "$4(R13)", base: "R13", off: 4},
		{text: "$(-64*1024+104)(R13)", base: "R13", off: -64*1024 + 104},
		{text: "$(12+4)(R4)", base: "R4", off: 16},
	} {
		op, err := ParseOperand(tc.text)
		if err != nil || op.Kind != OpSym {
			t.Fatalf("parseOperand(%q) = (%#v, %v), want address symbol", tc.text, op, err)
		}
		mem, ok := ParseMem(strings.TrimPrefix(op.Sym, "$"))
		if !ok || mem.Base != tc.base || mem.Off != tc.off {
			t.Fatalf("parseMem(%q) = (%#v, %v), want base=%s off=%d", tc.text, mem, ok, tc.base, tc.off)
		}
		if got := OperandClass(ArchARM, "arm", op); !strings.HasPrefix(got, "address.memory.") {
			t.Fatalf("operandClass(%q) = %q, want address.memory.*", tc.text, got)
		}
	}

	if op, err := ParseOperand("$(1<<24)"); err != nil || op.Kind != OpImm || op.Imm != 1<<24 || op.ImmRaw != "" {
		t.Fatalf("parseOperand(constant expression) = (%#v, %v)", op, err)
	}
}
