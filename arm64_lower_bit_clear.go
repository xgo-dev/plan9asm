package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64BitClear(op Op, ins Instr) (ok bool, terminated bool, err error) {
	word := op == "BICW" || op == "BICSW"
	setFlags := op == "BICS" || op == "BICSW"
	if !word && !setFlags && op != "BIC" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	if !arm64BitClearSourceValid(ins.Args[0], word) {
		return true, false, fmt.Errorf("arm64 %s invalid first operand: %q", op, ins.Raw)
	}

	destinationIndex := len(ins.Args) - 1
	destination := ins.Args[destinationIndex]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s destination must be a register: %q", op, ins.Raw)
	}
	destinationGeneral := isARM64GeneralOrZeroReg(destination.Reg)
	destinationStack := destination.Reg == SP || destination.Reg == Reg("RSP")
	if !destinationGeneral && !(len(ins.Args) == 3 && !setFlags && ins.Args[0].Kind == OpImm && destinationStack) {
		return true, false, fmt.Errorf("arm64 %s invalid destination register: %q", op, ins.Raw)
	}

	leftOperand := destination
	if len(ins.Args) == 3 {
		leftOperand = ins.Args[1]
		if leftOperand.Kind != OpReg || !isARM64GeneralOrZeroReg(leftOperand.Reg) {
			return true, false, fmt.Errorf("arm64 %s second operand must be a general register: %q", op, ins.Raw)
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
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i32 %s, -1\n", inverted, right)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %%%s\n", result, left, inverted)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
		if err := c.storeReg(destination.Reg, "%"+wide); err != nil {
			return true, false, err
		}
		if setFlags {
			c.setFlagsLogic32("%" + result)
		}
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
	inverted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i64 %s, -1\n", inverted, right)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %s, %%%s\n", result, left, inverted)
	if err := c.storeReg(destination.Reg, "%"+result); err != nil {
		return true, false, err
	}
	if setFlags {
		c.setFlagsLogic("%" + result)
	}
	return true, false, nil
}

func arm64BitClearSourceValid(operand Operand, word bool) bool {
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
		case ShiftLeft, ShiftRight, ShiftArith, ShiftRotate:
		default:
			return false
		}
		limit := int64(63)
		if word {
			limit = 31
		}
		return operand.ShiftAmount >= 0 && operand.ShiftAmount <= limit
	default:
		return false
	}
}
