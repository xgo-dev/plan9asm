package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64ScalarFloatCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "FCMPS", "FCMPD", "FCMPES", "FCMPED":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[1].Kind != OpReg || !isARM64FReg(ins.Args[1].Reg) ||
		!arm64ScalarFloatCompareSource(ins.Args[0]) {
		return true, false, fmt.Errorf("arm64 %s expects Fsrc or $(0.0), Fdst and no suffix: %q", op, ins.Raw)
	}

	bits := 64
	typeName := "double"
	if op == "FCMPS" || op == "FCMPES" {
		bits = 32
		typeName = "float"
	}
	right := formatLLVMFloat64Literal(0)
	if ins.Args[0].Kind == OpReg {
		right, err = c.loadARM64ScalarFloatReg(ins.Args[0].Reg, bits)
		if err != nil {
			return true, false, err
		}
	}
	left, err := c.loadARM64ScalarFloatReg(ins.Args[1].Reg, bits)
	if err != nil {
		return true, false, err
	}
	c.setARM64FloatCompareFlags(typeName, left, right)
	return true, false, nil
}

func arm64ScalarFloatCompareSource(operand Operand) bool {
	if operand.Kind == OpReg {
		return isARM64FReg(operand.Reg)
	}
	// Go's C_FCON optab class accepts any floating constant here even though
	// AArch64's FCMP-immediate encoding always compares against zero. Preserve
	// that assembler behavior instead of treating the source spelling as the
	// value encoded by the instruction.
	return operand.Kind == OpImm && operand.ImmRaw == "" && operand.ImmIsFloat
}

func (c *arm64Ctx) setARM64FloatCompareFlags(typeName, left, right string) {
	equal := c.newTmp()
	less := c.newTmp()
	greater := c.newTmp()
	unordered := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp oeq %s %s, %s\n", equal, typeName, left, right)
	fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %s, %s\n", less, typeName, left, right)
	fmt.Fprintf(c.b, "  %%%s = fcmp ogt %s %s, %s\n", greater, typeName, left, right)
	fmt.Fprintf(c.b, "  %%%s = fcmp uno %s %s, %s\n", unordered, typeName, left, right)
	greaterOrEqual := c.newTmp()
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", greaterOrEqual, greater, equal)
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", carry, greaterOrEqual, unordered)
	c.flagsWritten = true
	c.storeFlag(c.flagsNSlot, "%"+less)
	c.storeFlag(c.flagsZSlot, "%"+equal)
	c.storeFlag(c.flagsCSlot, "%"+carry)
	c.storeFlag(c.flagsVSlot, "%"+unordered)
}
