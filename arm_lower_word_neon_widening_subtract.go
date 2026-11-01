package plan9asm

import "fmt"

type armRawNEONWideningSubtract struct {
	operation   string
	unsigned    bool
	elementBits int
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawNEONWideningAddSub covers complete A32 VADDL/VSUBL signed and
// unsigned register families: 8-, 16-, and 32-bit D lanes widened into a Q
// destination before the arithmetic operation.
func decodeARMRawNEONWideningAddSub(word uint32) (armRawNEONWideningSubtract, bool) {
	operation := ""
	switch word & 0xfe800f50 {
	case 0xf2800000:
		operation = "add"
	case 0xf2800200:
		operation = "sub"
	default:
		return armRawNEONWideningSubtract{}, false
	}
	size := int(word>>20) & 3
	if size == 3 {
		return armRawNEONWideningSubtract{}, false
	}
	destination := int(word>>12)&15 | int(word>>22&1)*16
	// A Q register is encoded as its even-numbered first D register.
	if destination&1 != 0 {
		return armRawNEONWideningSubtract{}, false
	}
	return armRawNEONWideningSubtract{
		operation:   operation,
		unsigned:    word>>24&1 != 0,
		elementBits: 8 << size,
		destination: destination,
		lhs:         int(word>>16)&15 | int(word>>7&1)*16,
		rhs:         int(word)&15 | int(word>>5&1)*16,
	}, true
}

func decodeARMRawNEONWideningSubtract(word uint32) (armRawNEONWideningSubtract, bool) {
	form, ok := decodeARMRawNEONWideningAddSub(word)
	return form, ok && form.operation == "sub"
}

func (c *armCtx) lowerRawNEONWideningAddSub(form armRawNEONWideningSubtract) error {
	lhsBits, err := c.loadFReg(armRawVFPBackingReg(form.lhs, 64))
	if err != nil {
		return err
	}
	rhsBits, err := c.loadFReg(armRawVFPBackingReg(form.rhs, 64))
	if err != nil {
		return err
	}
	lanes := 64 / form.elementBits
	wideBits := form.elementBits * 2
	lhsVector := c.newTmp()
	rhsVector := c.newTmp()
	lhsWide := c.newTmp()
	rhsWide := c.newTmp()
	result := c.newTmp()
	resultBits := c.newTmp()
	extend := "sext"
	if form.unsigned {
		extend = "zext"
	}
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <%d x i%d>\n", lhsVector, lhsBits, lanes, form.elementBits)
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <%d x i%d>\n", rhsVector, rhsBits, lanes, form.elementBits)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %%%s to <%d x i%d>\n", lhsWide, extend, lanes, form.elementBits, lhsVector, lanes, wideBits)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %%%s to <%d x i%d>\n", rhsWide, extend, lanes, form.elementBits, rhsVector, lanes, wideBits)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %%%s, %%%s\n",
		result, form.operation, lanes, wideBits, lhsWide, rhsWide)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to i128\n", resultBits, lanes, wideBits, result)
	low := c.newTmp()
	highWide := c.newTmp()
	high := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", low, resultBits)
	fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", highWide, resultBits)
	fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", high, highWide)
	if err := c.storeFReg(armRawVFPBackingReg(form.destination, 64), "%"+low); err != nil {
		return err
	}
	return c.storeFReg(armRawVFPBackingReg(form.destination+1, 64), "%"+high)
}
