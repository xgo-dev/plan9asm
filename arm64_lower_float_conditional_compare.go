package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64FloatConditionalCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "FCCMPS", "FCCMPD", "FCCMPES", "FCCMPED":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects condition, Fsrc, Fdst, $NZCV(0..15) and no suffix: %q", op, ins.Raw)
	}
	condition, conditionOK := arm64FloatConditionalCompareCondition(ins.Args[0])
	if !conditionOK ||
		ins.Args[1].Kind != OpReg || !isARM64FReg(ins.Args[1].Reg) ||
		ins.Args[2].Kind != OpReg || !isARM64FReg(ins.Args[2].Reg) ||
		ins.Args[3].Kind != OpImm || ins.Args[3].ImmRaw != "" || ins.Args[3].Imm < 0 || ins.Args[3].Imm > 15 {
		return true, false, fmt.Errorf("arm64 %s expects condition, Fsrc, Fdst, $NZCV(0..15) and no suffix: %q", op, ins.Raw)
	}
	predicate, err := c.condValue(condition)
	if err != nil {
		return true, false, err
	}

	bits := 64
	typeName := "double"
	if op == "FCCMPS" || op == "FCCMPES" {
		bits = 32
		typeName = "float"
	}
	right, err := c.loadARM64ScalarFloatReg(ins.Args[1].Reg, bits)
	if err != nil {
		return true, false, err
	}
	left, err := c.loadARM64ScalarFloatReg(ins.Args[2].Reg, bits)
	if err != nil {
		return true, false, err
	}

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

	nzcv := ins.Args[3].Imm
	selectFlag := func(computed string, fallback bool) string {
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %t\n", selected, predicate, computed, fallback)
		return "%" + selected
	}
	c.flagsWritten = true
	c.storeFlag(c.flagsNSlot, selectFlag("%"+less, nzcv&8 != 0))
	c.storeFlag(c.flagsZSlot, selectFlag("%"+equal, nzcv&4 != 0))
	c.storeFlag(c.flagsCSlot, selectFlag("%"+carry, nzcv&2 != 0))
	c.storeFlag(c.flagsVSlot, selectFlag("%"+unordered, nzcv&1 != 0))
	return true, false, nil
}

func arm64FloatConditionalCompareCondition(operand Operand) (string, bool) {
	if operand.Kind == OpIdent {
		return operand.Ident, true
	}
	// AL is both an ARM64 condition and an x86 byte register. The parser keeps
	// machine-register spellings architecture independent, so this condition is
	// the only C_COND value represented as OpReg in ARM64 assembly.
	if operand.Kind == OpReg && strings.EqualFold(string(operand.Reg), "AL") {
		return "AL", true
	}
	return "", false
}
