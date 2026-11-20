package plan9asm

import (
	"strings"
	"testing"
)

func TestARM64LDEORCompleteFamily(t *testing.T) {
	c, b := newARM64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.ldeor", Ret: Void}, nil)
	for _, register := range []Reg{"R0", "R1", "R2"} {
		if err := c.storeReg(register, "1"); err != nil {
			t.Fatal(err)
		}
	}
	mem := arm64MemOp("R1", 0)
	ops := []Op{
		"LDEORB", "LDEORH", "LDEORW", "LDEORD",
		"LDEORAB", "LDEORAH", "LDEORAW", "LDEORAD",
		"LDEORLB", "LDEORLH", "LDEORLW", "LDEORLD",
		"LDEORALB", "LDEORALH", "LDEORALW", "LDEORALD",
	}
	for _, op := range ops {
		instruction := Instr{Op: op, Args: []Operand{arm64RegOp("R0"), mem, arm64RegOp("R2")}, Raw: string(op) + " R0, (R1), R2"}
		ok, terminated, err := c.lowerAtomic(op, instruction)
		if err != nil || !ok || terminated {
			t.Fatalf("lowerAtomic(%s) = (%v, %v, %v)", op, ok, terminated, err)
		}
	}
	out := b.String()
	if got := strings.Count(out, "atomicrmw xor"); got != len(ops) {
		t.Fatalf("atomicrmw xor count = %d, want %d\n%s", got, len(ops), out)
	}
	for _, ty := range []string{"i8", "i16", "i32", "i64"} {
		if !strings.Contains(out, "atomicrmw xor ptr") || !strings.Contains(out, ", "+ty+" ") {
			t.Fatalf("missing %s LDEOR lowering:\n%s", ty, out)
		}
	}
}

func TestARM64LDEORRejectsInvalidForms(t *testing.T) {
	c, _ := newARM64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.ldeor.invalid", Ret: Void}, nil)
	for _, instruction := range []Instr{
		{Op: "LDEORALW", Args: []Operand{arm64RegOp("R0"), arm64MemOp("R1", 0)}, Raw: "LDEORALW R0, (R1)"},
		{Op: "LDEORALW", Args: []Operand{arm64RegOp("R0"), arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "LDEORALW R0, R1, R2"},
	} {
		ok, _, err := c.lowerAtomic(instruction.Op, instruction)
		if !ok || err == nil {
			t.Fatalf("lowerAtomic(%q) = (%v, %v), want handled error", instruction.Raw, ok, err)
		}
	}
}
