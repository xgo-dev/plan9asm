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

func TestARMNumberedRegisterOperands(t *testing.T) {
	for _, tc := range []struct{ numbered, direct string }{
		{"R(1)<<R(2)", "R1<<R2"},
		{"R(09)", "R9"},
		{"F(15)", "F15"},
		{"4(R(3))", "4(R3)"},
	} {
		want, err := parseOperandForArch(ArchARM, tc.direct)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseOperandForArch(ArchARM, tc.numbered)
		if err != nil || got.String() != want.String() || got.Kind != want.Kind {
			t.Errorf("%s parsed as %v, %v; want %v", tc.numbered, got, err, want)
		}
	}
	if _, err := parseOperandForArch(ArchARM, "R(16)"); err == nil {
		t.Error("R(16) accepted")
	}
}

func TestAssemblyDataAndGlobalConstants(t *testing.T) {
	for _, tc := range []struct {
		width string
		arg   string
		want  uint64
	}{
		{"4", "$1.5", 0x3fc00000}, {"8", "$-1.5", 0xbff8000000000000}, {"1", "$'a'", 97},
	} {
		ds, err := ParseDATAStmt(ArchARM64, "value(SB)/"+tc.width+", "+tc.arg)
		if err != nil || ds.Value != tc.want {
			t.Errorf("DATA /%s %s = %#x, %v", tc.width, tc.arg, ds.Value, err)
		}
	}
	for _, src := range []string{"value(SB)/4, $(unknown + 12)", "value(SB)/2, $1.5", "value(SB)/3, $17"} {
		if _, err := ParseDATAStmt(ArchARM64, src); err == nil {
			t.Errorf("accepted DATA %s", src)
		}
	}
	for _, expr := range []string{"$(macro)", "$(macro + 4)"} {
		g, err := parseGLOBLStmt("value(SB)," + expr)
		if err != nil || g.Size >= 0 {
			t.Errorf("GLOBL %s received invented size %d, err=%v", expr, g.Size, err)
		}
	}
}
