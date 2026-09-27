package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64DivideRemainder(op Op, ins Instr) (ok bool, terminated bool, err error) {
	var llvmOp string
	var word, signed, remainder bool
	switch op {
	case "SDIV":
		llvmOp, signed = "sdiv", true
	case "SDIVW":
		llvmOp, signed, word = "sdiv", true, true
	case "UDIV":
		llvmOp = "udiv"
	case "UDIVW":
		llvmOp, word = "udiv", true
	case "REM":
		llvmOp, signed, remainder = "srem", true, true
	case "REMW":
		llvmOp, signed, remainder, word = "srem", true, true, true
	case "UREM":
		llvmOp, remainder = "urem", true
	case "UREMW":
		llvmOp, remainder, word = "urem", true, true
	default:
		return false, false, nil
	}

	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
			return true, false, fmt.Errorf("arm64 %s expects only general registers: %q", op, ins.Raw)
		}
	}

	divisor, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	dividendOperand := ins.Args[1]
	destination := ins.Args[1].Reg
	if len(ins.Args) == 3 {
		destination = ins.Args[2].Reg
	}
	dividend, err := c.loadReg(dividendOperand.Reg)
	if err != nil {
		return true, false, err
	}

	typeName := "i64"
	minimum := "-9223372036854775808"
	if word {
		typeName = "i32"
		minimum = "-2147483648"
		truncatedDivisor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncatedDivisor, divisor)
		divisor = "%" + truncatedDivisor
		truncatedDividend := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncatedDividend, dividend)
		dividend = "%" + truncatedDividend
	}

	isZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", isZero, typeName, divisor)
	unsafeDivisor := "%" + isZero
	if signed {
		isMinimum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", isMinimum, typeName, dividend, minimum)
		isMinusOne := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, -1\n", isMinusOne, typeName, divisor)
		isOverflow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isOverflow, isMinimum, isMinusOne)
		unsafe := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", unsafe, isZero, isOverflow)
		unsafeDivisor = "%" + unsafe
	}

	safeDivisor := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s 1, %s %s\n", safeDivisor, unsafeDivisor, typeName, typeName, divisor)
	computed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", computed, llvmOp, typeName, dividend, safeDivisor)
	result := "%" + computed
	selected := c.newTmp()
	if remainder {
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", selected, isZero, typeName, dividend, typeName, result)
	} else {
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %s\n", selected, isZero, typeName, typeName, result)
	}
	result = "%" + selected
	if word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, result)
		result = "%" + wide
	}
	return true, false, c.storeReg(destination, result)
}
