package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64AddSubCarry(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "ADC", "ADCW", "ADCS", "ADCSW", "SBC", "SBCW", "SBCS", "SBCSW":
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	if !arm64AddSubCarryRegisterOrZero(ins.Args[0], true) {
		return true, false, fmt.Errorf("arm64 %s first operand must be a general register or zero: %q", op, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if !arm64AddSubCarryRegisterOrZero(destination, false) {
		return true, false, fmt.Errorf("arm64 %s destination must be a general register: %q", op, ins.Raw)
	}
	leftOperand := destination
	if len(ins.Args) == 3 {
		leftOperand = ins.Args[1]
		if !arm64AddSubCarryRegisterOrZero(leftOperand, false) {
			return true, false, fmt.Errorf("arm64 %s second operand must be a general register: %q", op, ins.Raw)
		}
	}

	word := strings.HasSuffix(string(op), "W")
	subtract := strings.HasPrefix(string(op), "SBC")
	setFlags := op == "ADCS" || op == "ADCSW" || op == "SBCS" || op == "SBCSW"
	if word {
		return c.lowerARM64AddSubCarry32(op, ins, leftOperand, destination, subtract, setFlags)
	}
	return c.lowerARM64AddSubCarry64(op, ins, leftOperand, destination, subtract, setFlags)
}

func arm64AddSubCarryRegisterOrZero(operand Operand, allowImmediateZero bool) bool {
	if operand.Kind == OpReg {
		return isARM64GeneralOrZeroReg(operand.Reg)
	}
	return allowImmediateZero && operand.Kind == OpImm && operand.Imm == 0 && operand.ImmRaw == ""
}

func (c *arm64Ctx) lowerARM64AddSubCarry32(op Op, ins Instr, leftOperand, destination Operand, subtract, setFlags bool) (bool, bool, error) {
	right, err := c.eval32(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	left, err := c.eval32(leftOperand)
	if err != nil {
		return true, false, err
	}
	carryFlag := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", carryFlag, c.flagsCSlot)
	carryOrBorrow := "%" + carryFlag
	if subtract {
		borrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", borrow, carryFlag)
		carryOrBorrow = "%" + borrow
	}
	amount := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", amount, carryOrBorrow)
	intermediate := c.newTmp()
	result := c.newTmp()
	if subtract {
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", intermediate, left, right)
		fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, %%%s\n", result, intermediate, amount)
	} else {
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", intermediate, left, right)
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", result, intermediate, amount)
	}
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
	if err := c.storeReg(destination.Reg, "%"+wide); err != nil {
		return true, false, err
	}
	if !setFlags {
		return true, false, nil
	}
	if subtract {
		borrow0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %s, %s\n", borrow0, left, right)
		borrow1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %%%s, %%%s\n", borrow1, intermediate, amount)
		borrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", borrow, borrow0, borrow1)
		noBorrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", noBorrow, borrow)
		c.setFlagsSub32WithCarry(left, right, "%"+result, "%"+noBorrow)
	} else {
		carry0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %%%s, %s\n", carry0, intermediate, left)
		carry1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %%%s, %%%s\n", carry1, result, intermediate)
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", carry, carry0, carry1)
		c.setFlagsAdd32WithCarry(left, right, "%"+result, "%"+carry)
	}
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64AddSubCarry64(op Op, ins Instr, leftOperand, destination Operand, subtract, setFlags bool) (bool, bool, error) {
	right, err := c.eval64(ins.Args[0], false)
	if err != nil {
		return true, false, err
	}
	left, err := c.eval64(leftOperand, false)
	if err != nil {
		return true, false, err
	}
	carryFlag := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", carryFlag, c.flagsCSlot)
	carryOrBorrow := "%" + carryFlag
	if subtract {
		borrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", borrow, carryFlag)
		carryOrBorrow = "%" + borrow
	}
	amount := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", amount, carryOrBorrow)
	intermediate := c.newTmp()
	result := c.newTmp()
	if subtract {
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", intermediate, left, right)
		fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, %%%s\n", result, intermediate, amount)
	} else {
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", intermediate, left, right)
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", result, intermediate, amount)
	}
	if err := c.storeReg(destination.Reg, "%"+result); err != nil {
		return true, false, err
	}
	if !setFlags {
		return true, false, nil
	}
	if subtract {
		borrow0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", borrow0, left, right)
		borrow1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %%%s\n", borrow1, intermediate, amount)
		borrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", borrow, borrow0, borrow1)
		noBorrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", noBorrow, borrow)
		c.setFlagsSubWithCarry(left, right, "%"+result, "%"+noBorrow)
	} else {
		carry0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %s\n", carry0, intermediate, left)
		carry1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %%%s\n", carry1, result, intermediate)
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", carry, carry0, carry1)
		c.setFlagsAddWithCarry(left, right, "%"+result, "%"+carry)
	}
	return true, false, nil
}
