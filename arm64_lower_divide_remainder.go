package plan9asm

import "fmt"

func (c *arm64Ctx) lowerARM64DivideRemainder(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, handled, err := parseARM64DivideRemainderForm(op, ins)
	if !handled || err != nil {
		return handled, false, err
	}
	width := 64
	if form.word {
		width = 32
	}
	divisor, err := c.loadRegisterWidth(form.divisor.Reg, width)
	if err != nil {
		return true, false, err
	}
	dividend, err := c.loadRegisterWidth(form.dividend.Reg, width)
	if err != nil {
		return true, false, err
	}

	typeName := "i64"
	minimum := "-9223372036854775808"
	if form.word {
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
	if form.signed {
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
	llvmOp := "udiv"
	if form.signed {
		llvmOp = "sdiv"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", computed, llvmOp, typeName, dividend, safeDivisor)
	result := "%" + computed
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %s\n", selected, isZero, typeName, typeName, result)
	result = "%" + selected
	if form.word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, result)
		result = "%" + wide
	}
	if !form.remainder {
		return true, false, c.storeReg(form.destination.Reg, result)
	}
	if err := c.storeReg("R27", result); err != nil {
		return true, false, err
	}
	// Go's second machine instruction observes the DIV write when either
	// source is R27. Capture neither source from its pre-DIV LLVM value.
	divisor, err = c.loadRegisterWidth(form.divisor.Reg, width)
	if err != nil {
		return true, false, err
	}
	dividend, err = c.loadRegisterWidth(form.dividend.Reg, width)
	if err != nil {
		return true, false, err
	}
	if form.word {
		for _, value := range []*string{&divisor, &dividend, &result} {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, *value)
			*value = "%" + narrow
		}
	}
	product, difference := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, typeName, result, divisor)
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, %%%s\n", difference, typeName, dividend, product)
	result = "%" + difference
	if form.word {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, result)
		result = "%" + wide
	}
	return true, false, c.storeReg(form.destination.Reg, result)
}
