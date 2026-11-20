package plan9asm

import "fmt"

func (c *amd64Ctx) lowerANDN(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86TernaryGPProperties(op, ins, c.goarch)
	if !known || form.spec.operation != x86TernaryANDN {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	typ := amd64IntegerTypeForBits(form.spec.bits)
	first, err := c.evalSizedNativeGPSource(form.first, typ, ins.x86AddressBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.evalIntSized(form.second, typ)
	if err != nil {
		return true, false, err
	}
	inverted, result := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typ, second)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", result, typ, inverted, first)
	if typ == I64 {
		c.setZSFlagsFromI64("%" + result)
	} else {
		c.setZSFlagsFromI32("%" + result)
	}
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return true, false, c.storeRegSized(form.destination.Reg, typ, "%"+result)
}
