package plan9asm

import "fmt"

// lowerLowestSetBitManipulation implements Go 1.27's complete _yblsil table:
// BLSI, BLSMSK, and BLSR at L/Q widths, with a Yml register-or-memory source
// and a Yrl destination register.
func (c *amd64Ctx) lowerLowestSetBitManipulation(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86BLSProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	typ := amd64IntegerTypeForBits(form.spec.bits)
	value, err := c.evalBLSSource(ins, form, typ)
	if err != nil {
		return true, false, err
	}
	minusOne := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, 1\n", minusOne, typ, value)
	result := c.newTmp()
	carry := ""
	switch form.spec.kind {
	case x86BLSIsolate:
		negative := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", negative, typ, value)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, value, negative)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, 0\n", carry, typ, value)
	case x86BLSMask:
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", result, typ, value, minusOne)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", carry, typ, value)
	case x86BLSReset:
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, value, minusOne)
		carry = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", carry, typ, value)
	}

	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	if form.spec.kind == x86BLSMask {
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsZSlot)
	} else {
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	}
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return true, false, c.storeRegSized(form.destination.Reg, typ, "%"+result)
}
