package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64AddFlags(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ADDS" && op != "ADDSW" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	word := op == "ADDSW"
	if !arm64AddFlagsSourceValid(ins.Args[0], word) {
		return true, false, fmt.Errorf("arm64 %s invalid first operand: %q", op, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg || !isARM64GeneralOrZeroReg(destination.Reg) {
		return true, false, fmt.Errorf("arm64 %s destination must be a general register: %q", op, ins.Raw)
	}
	leftOperand := destination
	if len(ins.Args) == 3 {
		leftOperand = ins.Args[1]
		leftGeneral := leftOperand.Kind == OpReg && isARM64GeneralOrZeroReg(leftOperand.Reg)
		leftStack := leftOperand.Kind == OpReg && (leftOperand.Reg == SP || leftOperand.Reg == Reg("RSP"))
		if !leftGeneral && !leftStack {
			return true, false, fmt.Errorf("arm64 %s second operand must be a general or stack register: %q", op, ins.Raw)
		}
		if leftStack && ins.Args[0].Kind == OpRegShift &&
			(ins.Args[0].ShiftOp != ShiftLeft || ins.Args[0].ShiftAmount > 4) {
			return true, false, fmt.Errorf("arm64 %s with RSP accepts only a left-shifted register by 0..4: %q", op, ins.Raw)
		}
	}

	if word {
		right, err := c.eval32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		left, err := c.eval32(leftOperand)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", result, left, right)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
		if err := c.storeReg(destination.Reg, "%"+wide); err != nil {
			return true, false, err
		}
		c.setFlagsAdd32(left, right, "%"+result)
		return true, false, nil
	}

	right, err := c.eval64(ins.Args[0], false)
	if err != nil {
		return true, false, err
	}
	left, err := c.eval64(leftOperand, false)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", result, left, right)
	if err := c.storeReg(destination.Reg, "%"+result); err != nil {
		return true, false, err
	}
	c.setFlagsAdd(left, right, "%"+result)
	return true, false, nil
}

func arm64AddFlagsSourceValid(operand Operand, word bool) bool {
	switch operand.Kind {
	case OpImm:
		return operand.ImmRaw == ""
	case OpReg:
		return isARM64GeneralOrZeroReg(operand.Reg)
	case OpRegShift:
		if !isARM64GeneralOrZeroReg(operand.Reg) || operand.ShiftReg != "" {
			return false
		}
		switch operand.ShiftOp {
		case ShiftLeft, ShiftRight, ShiftArith:
		default:
			return false
		}
		limit := int64(63)
		if word {
			limit = 31
		}
		return operand.ShiftAmount >= 0 && operand.ShiftAmount <= limit
	case OpRegExtend:
		if !isARM64GeneralOrZeroReg(operand.Reg) || operand.ShiftReg != "" {
			return false
		}
		switch operand.Ext {
		case ExtendUXTB, ExtendUXTH, ExtendUXTW, ExtendUXTX,
			ExtendSXTB, ExtendSXTH, ExtendSXTW, ExtendSXTX:
		default:
			return false
		}
		return (operand.ShiftOp == "" || operand.ShiftOp == ShiftLeft) && operand.ShiftAmount >= 0 && operand.ShiftAmount <= 4
	default:
		return false
	}
}
