package plan9asm

import "fmt"

// lowerBZHI implements Go 1.27's complete _ybextrl operand row for BZHIL/Q:
// register index, register/memory source, and register destination.
func (c *amd64Ctx) lowerBZHI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86ScalarBitFieldFamilyProperties(op, ins, c.goarch, x86BitFieldZeroHigh)
	if !known || err != nil {
		return known, false, err
	}

	bits := form.bits
	typ := amd64IntegerTypeForBits(bits)
	indexValue, err := c.evalIntSized(form.control, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, err := c.evalScalarBitFieldSource(ins, form, typ)
	if err != nil {
		return true, false, err
	}
	indexLowByte := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, 255\n", indexLowByte, typ, indexValue)
	indexInRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %d\n", indexInRange, typ, indexLowByte, bits)
	safeIndex := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", safeIndex, typ, indexLowByte, bits-1)
	one := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", one, typ, safeIndex)
	partialMask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, -1\n", partialMask, typ, one)
	mask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s -1\n", mask, indexInRange, typ, partialMask, typ)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, sourceValue, mask)
	if err := c.storeRegSized(form.destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", carry, indexInRange)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	return true, false, nil
}
