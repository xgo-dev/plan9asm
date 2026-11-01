package plan9asm

import (
	"fmt"
	"strings"
)

type arm64ConditionalCompareForm struct {
	arm64ScalarCompareForm
	condition string
	nzcv      uint8
}

// Go asm7 case 57 inherits one C_COND,FREG,FREG,VCON row across four
// names. Half precision belongs only to the independently decoded WORD role.
var arm64ConditionalCompareOps = map[Op]arm64ScalarCompareForm{
	"FCCMPS":  {bits: 32},
	"FCCMPD":  {bits: 64},
	"FCCMPES": {bits: 32, signaling: true},
	"FCCMPED": {bits: 64, signaling: true},
}

func parseARM64ConditionalCompare(op Op, ins Instr) (arm64ConditionalCompareForm, bool, error) {
	scalar, known := arm64ConditionalCompareOps[op]
	if !known {
		return arm64ConditionalCompareForm{}, false, nil
	}
	invalid := func() (arm64ConditionalCompareForm, bool, error) {
		return arm64ConditionalCompareForm{}, true, fmt.Errorf("arm64 %s expects condition, Fsrc, Fdst, $NZCV(0..15) and no suffix: %q", op, ins.Raw)
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return invalid()
	}
	condition, valid := arm64FloatConditionalCompareCondition(ins.Args[0])
	if !valid || ins.Args[1].Kind != OpReg || !isARM64FReg(ins.Args[1].Reg) ||
		ins.Args[2].Kind != OpReg || !isARM64FReg(ins.Args[2].Reg) ||
		ins.Args[3].Kind != OpImm || ins.Args[3].ImmRaw != "" || ins.Args[3].ImmIsFloat ||
		ins.Args[3].Imm < 0 || ins.Args[3].Imm > 15 {
		return invalid()
	}
	if _, err := arm64ConditionFlags(condition); err != nil {
		return invalid()
	}
	scalar.left, scalar.right = ins.Args[2].Reg, ins.Args[1].Reg
	return arm64ConditionalCompareForm{scalar, condition, uint8(ins.Args[3].Imm)}, true, nil
}

func (c *arm64Ctx) lowerARM64FloatConditionalCompare(op Op, ins Instr) (bool, bool, error) {
	form, known, err := parseARM64ConditionalCompare(op, ins)
	if !known || err != nil {
		return known, false, err
	}
	return true, false, c.lowerARM64ConditionalCompare(form)
}

func (c *arm64Ctx) lowerARM64ConditionalCompare(form arm64ConditionalCompareForm) error {
	if err := requireARM64ScalarCompareTarget("arm64", c.targetTriple); err != nil {
		return err
	}
	// Consume only the source-defined condition bits. Never borrow entry NZCV.
	predicate, err := c.condValue(form.condition)
	if err != nil {
		return err
	}
	left, err := c.loadARM64ScalarFloatReg(form.left, form.bits)
	if err != nil {
		return err
	}
	right, err := c.loadARM64ScalarFloatReg(form.right, form.bits)
	if err != nil {
		return err
	}
	typeName, _, valid := arm64ScalarFloatType(form.bits)
	if !valid {
		return fmt.Errorf("arm64 unsupported conditional float width %d", form.bits)
	}
	modifier := map[int]string{16: "h", 32: "s", 64: "d"}[form.bits]
	opcode := "fccmp"
	if form.signaling {
		opcode = "fccmpe"
	}
	condition, flags := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", condition, predicate)
	// DDI0602: the condition gates FPCompare itself, including FPCR/FPSR and
	// exception delivery. A pure fcmp followed by select is not equivalent.
	// Seed a private native NE predicate from the proved virtual condition and
	// capture the resulting NZCV in this indivisible block. No SIMD bytes change.
	assembly := fmt.Sprintf("cmp ${3:w}, #0\\0A%s ${1:%s}, ${2:%s}, #%d, ne\\0Amrs $0, nzcv", opcode, modifier, modifier, form.nzcv)
	c.emitMachineNeutralNativeIR("  %%%s = call i64 asm sideeffect \"%s\", \"=r,w,w,r,~{cc},~{memory}\"(%s %s, %s %s, i32 %%%s)\n", flags, assembly, typeName, left, typeName, right, condition)
	c.storeARM64NativeCompareFlags("%" + flags)
	return nil
}

func arm64FloatConditionalCompareCondition(operand Operand) (string, bool) {
	if operand.Kind == OpIdent {
		return operand.Ident, true
	}
	// AL is also an x86 byte-register spelling in the shared source parser.
	if operand.Kind == OpReg && strings.EqualFold(string(operand.Reg), "AL") {
		return "AL", true
	}
	return "", false
}
