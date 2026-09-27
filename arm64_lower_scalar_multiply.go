package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64ScalarMultiply implements the complete scalar multiply rows shared
// by Go 1.27's AMUL and AMADD optabs. In particular, the two-operand AMUL-row
// form uses the destination as the second multiplicand.
func (c *arm64Ctx) lowerARM64ScalarMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if spec, found := arm64MultiplyAccumulateOps[op]; found {
		if strings.ToUpper(string(ins.Op)) != string(op) {
			return true, false, fmt.Errorf("arm64 %s does not accept instruction suffixes: %q", op, ins.Raw)
		}
		if len(ins.Args) != 4 {
			return true, false, fmt.Errorf("arm64 %s expects four C_ZREG operands: %q", op, ins.Raw)
		}
		for _, operand := range ins.Args {
			if !arm64ScalarMultiplyRegister(operand) {
				return true, false, fmt.Errorf("arm64 %s expects four C_ZREG operands: %q", op, ins.Raw)
			}
		}
		return true, false, c.lowerARM64MultiplyAccumulate(spec, ins)
	}
	switch op {
	case "MNEG", "MNEGW", "SMULL", "UMULL", "SMNEGL", "UMNEGL", "SMULH", "UMULH":
		if strings.ToUpper(string(ins.Op)) != string(op) {
			return true, false, fmt.Errorf("arm64 %s does not accept instruction suffixes: %q", op, ins.Raw)
		}
		first, second, destination, err := c.arm64ScalarMultiplyOperands(op, ins)
		if err != nil {
			return true, false, err
		}
		switch op {
		case "MNEG", "MNEGW":
			return true, false, c.lowerARM64MultiplyNegate(op == "MNEGW", first, second, destination)
		case "SMULL", "UMULL", "SMNEGL", "UMNEGL":
			signed := op == "SMULL" || op == "SMNEGL"
			negate := op == "SMNEGL" || op == "UMNEGL"
			return true, false, c.lowerARM64MultiplyLong(signed, negate, first, second, destination)
		case "SMULH", "UMULH":
			return true, false, c.lowerARM64MultiplyHigh(op == "SMULH", first, second, destination)
		}

	}
	return false, false, nil
}

func (c *arm64Ctx) arm64ScalarMultiplyOperands(op Op, ins Instr) (Operand, Operand, Reg, error) {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return Operand{}, Operand{}, "", fmt.Errorf("arm64 %s expects two or three C_ZREG operands: %q", op, ins.Raw)
	}
	for _, operand := range ins.Args {
		if !arm64ScalarMultiplyRegister(operand) {
			return Operand{}, Operand{}, "", fmt.Errorf("arm64 %s expects two or three C_ZREG operands: %q", op, ins.Raw)
		}
	}
	if len(ins.Args) == 2 {
		return ins.Args[0], ins.Args[1], ins.Args[1].Reg, nil
	}
	return ins.Args[0], ins.Args[1], ins.Args[2].Reg, nil
}

func arm64ScalarMultiplyRegister(operand Operand) bool {
	return operand.Kind == OpReg && isARM64GeneralOrZeroReg(operand.Reg)
}

func (c *arm64Ctx) lowerARM64MultiplyNegate(word bool, first, second Operand, destination Reg) error {
	if word {
		a, err := c.eval32(first)
		if err != nil {
			return err
		}
		b, err := c.eval32(second)
		if err != nil {
			return err
		}
		product := c.newTmp()
		result := c.newTmp()
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", product, a, b)
		fmt.Fprintf(c.b, "  %%%s = sub i32 0, %%%s\n", result, product)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
		return c.storeReg(destination, "%"+wide)
	}
	a, err := c.eval64(first, false)
	if err != nil {
		return err
	}
	b, err := c.eval64(second, false)
	if err != nil {
		return err
	}
	product := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", product, a, b)
	fmt.Fprintf(c.b, "  %%%s = sub i64 0, %%%s\n", result, product)
	return c.storeReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64MultiplyLong(signed, negate bool, first, second Operand, destination Reg) error {
	a, err := c.eval32(first)
	if err != nil {
		return err
	}
	b, err := c.eval32(second)
	if err != nil {
		return err
	}
	extension := "zext"
	if signed {
		extension = "sext"
	}
	wideA := c.newTmp()
	wideB := c.newTmp()
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", wideA, extension, a)
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", wideB, extension, b)
	fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", product, wideA, wideB)
	value := "%" + product
	if negate {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 0, %s\n", result, value)
		value = "%" + result
	}
	return c.storeReg(destination, value)
}

func (c *arm64Ctx) lowerARM64MultiplyHigh(signed bool, first, second Operand, destination Reg) error {
	a, err := c.eval64(first, false)
	if err != nil {
		return err
	}
	b, err := c.eval64(second, false)
	if err != nil {
		return err
	}
	extension := "zext"
	if signed {
		extension = "sext"
	}
	wideA := c.newTmp()
	wideB := c.newTmp()
	product := c.newTmp()
	high := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s i64 %s to i128\n", wideA, extension, a)
	fmt.Fprintf(c.b, "  %%%s = %s i64 %s to i128\n", wideB, extension, b)
	fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", product, wideA, wideB)
	fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", high, product)
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", result, high)
	return c.storeReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64MultiplyAddLong(signed, subtract bool, first, second, addend Operand, destination Reg) error {
	a, err := c.eval32(first)
	if err != nil {
		return err
	}
	b, err := c.eval32(second)
	if err != nil {
		return err
	}
	cv, err := c.eval64(addend, false)
	if err != nil {
		return err
	}
	extension := "zext"
	if signed {
		extension = "sext"
	}
	wideA := c.newTmp()
	wideB := c.newTmp()
	product := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", wideA, extension, a)
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", wideB, extension, b)
	fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", product, wideA, wideB)
	if subtract {
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %%%s\n", result, cv, product)
	} else {
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", result, cv, product)
	}
	return c.storeReg(destination, "%"+result)
}
