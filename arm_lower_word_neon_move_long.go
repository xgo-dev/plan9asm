package plan9asm

import "fmt"

type armRawNEONMoveLong struct {
	unsigned    bool
	elementBits int
	destination int
	source      int
}

// decodeARMRawNEONMoveLong covers the complete A32 VMOVL family: signed and
// unsigned widening from 8-, 16-, or 32-bit lanes in a D register to a Q
// register.
func decodeARMRawNEONMoveLong(word uint32) (armRawNEONMoveLong, bool) {
	if word&0xfe800fd0 != 0xf2800a10 {
		return armRawNEONMoveLong{}, false
	}
	var elementBits int
	switch word >> 16 & 0x3f {
	case 0b001000:
		elementBits = 8
	case 0b010000:
		elementBits = 16
	case 0b100000:
		elementBits = 32
	default:
		return armRawNEONMoveLong{}, false
	}
	destination := int(word>>12)&15 | int(word>>22&1)*16
	if destination&1 != 0 {
		return armRawNEONMoveLong{}, false
	}
	return armRawNEONMoveLong{
		unsigned:    word>>24&1 != 0,
		elementBits: elementBits,
		destination: destination,
		source:      int(word)&15 | int(word>>5&1)*16,
	}, true
}

func (c *armCtx) lowerRawNEONMoveLong(form armRawNEONMoveLong) error {
	sourceBits, err := c.loadFReg(armRawVFPBackingReg(form.source, 64))
	if err != nil {
		return err
	}
	lanes := 64 / form.elementBits
	wideBits := form.elementBits * 2
	source := c.newTmp()
	result := c.newTmp()
	resultBits := c.newTmp()
	extend := "sext"
	if form.unsigned {
		extend = "zext"
	}
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <%d x i%d>\n", source, sourceBits, lanes, form.elementBits)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %%%s to <%d x i%d>\n", result, extend, lanes, form.elementBits, source, lanes, wideBits)
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
