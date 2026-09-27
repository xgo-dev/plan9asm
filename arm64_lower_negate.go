package plan9asm

import (
	"fmt"
	"strings"
)

// lowerNegate implements the complete Go 1.27 NEG and negate-with-carry
// families: NEG/NEGW/NEGS/NEGSW and NGC/NGCW/NGCS/NGCSW.
func (c *arm64Ctx) lowerNegate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(baseOp, '.'); dot >= 0 {
		baseOp = baseOp[:dot]
	}
	word, setFlags, withCarry, recognized := arm64NegateProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	originalOp := rawOp
	if ins.Op != "" {
		originalOp = strings.ToUpper(string(ins.Op))
	}
	if originalOp != baseOp {
		return true, false, fmt.Errorf("arm64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}

	if withCarry {
		return c.lowerNegateWithCarry(baseOp, word, setFlags, ins)
	}
	if len(ins.Args) != 1 && len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects source[, destination]: %q", baseOp, ins.Raw)
	}
	source := ins.Args[0]
	destination := source
	if len(ins.Args) == 2 {
		destination = ins.Args[1]
	}
	if err := validateARM64NegateSource(source, word); err != nil {
		return true, false, fmt.Errorf("arm64 %s source: %w: %q", baseOp, err, ins.Raw)
	}
	if destination.Kind != OpReg || !isARM64GeneralOrZeroReg(destination.Reg) {
		return true, false, fmt.Errorf("arm64 %s destination is outside Go 1.27's C_ZREG class: %q", baseOp, ins.Raw)
	}

	if word {
		sourceValue, err := c.eval32(source)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 0, %s\n", result, sourceValue)
		if setFlags {
			c.setFlagsSub32("0", sourceValue, "%"+result)
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
		return true, false, c.storeReg(destination.Reg, "%"+wide)
	}
	sourceValue, err := c.eval64(source, false)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 0, %s\n", result, sourceValue)
	if setFlags {
		c.setFlagsSub("0", sourceValue, "%"+result)
	}
	return true, false, c.storeReg(destination.Reg, "%"+result)
}

func arm64NegateProperties(op string) (word, setFlags, withCarry, ok bool) {
	switch op {
	case "NEG":
		return false, false, false, true
	case "NEGW":
		return true, false, false, true
	case "NEGS":
		return false, true, false, true
	case "NEGSW":
		return true, true, false, true
	case "NGC":
		return false, false, true, true
	case "NGCW":
		return true, false, true, true
	case "NGCS":
		return false, true, true, true
	case "NGCSW":
		return true, true, true, true
	default:
		return false, false, false, false
	}
}

func validateARM64NegateSource(source Operand, word bool) error {
	switch source.Kind {
	case OpReg:
		if !isARM64GeneralOrZeroReg(source.Reg) {
			return fmt.Errorf("operand is outside Go 1.27's C_ZREG class")
		}
		return nil
	case OpRegShift:
		if !isARM64GeneralOrZeroReg(source.Reg) || source.ShiftReg != "" {
			return fmt.Errorf("operand is outside Go 1.27's C_SHIFT class")
		}
		if source.ShiftOp != ShiftLeft && source.ShiftOp != ShiftRight && source.ShiftOp != ShiftArith {
			return fmt.Errorf("unsupported shift operator %q", source.ShiftOp)
		}
		maximum := int64(63)
		if word {
			maximum = 31
		}
		if source.ShiftAmount < 0 || source.ShiftAmount > maximum {
			return fmt.Errorf("shift amount %d is outside 0..%d", source.ShiftAmount, maximum)
		}
		return nil
	default:
		return fmt.Errorf("operand is outside Go 1.27's C_ZREG/C_SHIFT classes")
	}
}

func (c *arm64Ctx) lowerNegateWithCarry(op string, word, setFlags bool, ins Instr) (ok bool, terminated bool, err error) {
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[0].Reg) || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 %s expects C_ZREG source and destination: %q", op, ins.Raw)
	}
	typeName := LLVMType(I64)
	wideType := LLVMType("i128")
	if word {
		typeName = I32
		wideType = I64
	}
	var source string
	if word {
		source, err = c.eval32(ins.Args[0])
	} else {
		source, err = c.eval64(ins.Args[0], false)
	}
	if err != nil {
		return true, false, err
	}
	wideSource := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", wideSource, typeName, source, wideType)
	carry := c.newTmp()
	borrow := c.newTmp()
	wideBorrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", carry, c.flagsCSlot)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", borrow, carry)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to %s\n", wideBorrow, borrow, wideType)
	subtrahend := c.newTmp()
	wideResult := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", subtrahend, wideType, wideSource, wideBorrow)
	fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", wideResult, wideType, subtrahend)
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", result, wideType, wideResult, typeName)
	resultValue := "%" + result
	if setFlags {
		c.setNegateWithCarryFlags(typeName, wideType, source, resultValue, "%"+subtrahend)
	}
	stored := resultValue
	if word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, resultValue)
		stored = "%" + wide
	}
	return true, false, c.storeReg(ins.Args[1].Reg, stored)
}

func (c *arm64Ctx) setNegateWithCarryFlags(typeName, wideType LLVMType, source, result, wideSubtrahend string) {
	c.flagsWritten = true
	zero := c.newTmp()
	negative := c.newTmp()
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, typeName, result)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", negative, typeName, result)
	fmt.Fprintf(c.b, "  %%%s = icmp uge %s 0, %s\n", carry, wideType, wideSubtrahend)
	xorOperands := c.newTmp()
	xorResult := c.newTmp()
	overflowBits := c.newTmp()
	overflow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s 0, %s\n", xorOperands, typeName, source)
	fmt.Fprintf(c.b, "  %%%s = xor %s 0, %s\n", xorResult, typeName, result)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", overflowBits, typeName, xorOperands, xorResult)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", overflow, typeName, overflowBits)
	c.storeFlag(c.flagsNSlot, "%"+negative)
	c.storeFlag(c.flagsZSlot, "%"+zero)
	c.storeFlag(c.flagsCSlot, "%"+carry)
	c.storeFlag(c.flagsVSlot, "%"+overflow)
}
