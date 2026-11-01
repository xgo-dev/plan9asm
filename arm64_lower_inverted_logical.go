package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64InvertedLogical(op Op, ins Instr) (ok bool, terminated bool, err error) {
	word := op == "ORNW" || op == "EONW"
	exclusive := op == "EON" || op == "EONW"
	if !word && !exclusive && op != "ORN" {
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

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s destination must be a register: %q", op, ins.Raw)
	}
	destinationGeneral := isARM64GeneralOrZeroReg(destination.Reg)
	destinationStack := destination.Reg == SP || destination.Reg == Reg("RSP")
	if !destinationGeneral && !(len(ins.Args) == 3 && ins.Args[0].Kind == OpImm && destinationStack) {
		return true, false, fmt.Errorf("arm64 %s invalid destination register: %q", op, ins.Raw)
	}

	leftOperand := destination
	if len(ins.Args) == 3 {
		leftOperand = ins.Args[1]
		if leftOperand.Kind != OpReg || !isARM64GeneralOrZeroReg(leftOperand.Reg) {
			return true, false, fmt.Errorf("arm64 %s second operand must be a general register: %q", op, ins.Raw)
		}
	}

	typeName := "i64"
	right, err := c.eval64(ins.Args[0], false)
	if word {
		typeName = "i32"
		right, err = c.eval32(ins.Args[0])
	}
	if err != nil {
		return true, false, err
	}
	left, err := c.eval64(leftOperand, false)
	if word {
		left, err = c.eval32(leftOperand)
	}
	if err != nil {
		return true, false, err
	}

	inverted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typeName, right)
	llvmOp := "or"
	if exclusive {
		llvmOp = "xor"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, llvmOp, typeName, left, inverted)
	value := "%" + result
	if word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		value = "%" + wide
	}
	return true, false, c.storeReg(destination.Reg, value)
}
