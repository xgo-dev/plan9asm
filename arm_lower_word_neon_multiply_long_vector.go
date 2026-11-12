package plan9asm

import "fmt"

type armRawNEONMultiplyLongVector struct {
	kind        string
	unsigned    bool
	elementBits int
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawNEONMultiplyLongVector covers every signed and unsigned A32
// VMULL/VMLAL/VMLSL register form, for 8-, 16-, and 32-bit D-register lanes.
func decodeARMRawNEONMultiplyLongVector(word uint32) (armRawNEONMultiplyLongVector, bool) {
	kind := ""
	switch word & 0xfe800f50 {
	case 0xf2800c00:
		kind = "mul"
	case 0xf2800800:
		kind = "mla"
	case 0xf2800a00:
		kind = "mls"
	default:
		return armRawNEONMultiplyLongVector{}, false
	}
	size := int(word >> 20 & 3)
	if size == 3 {
		return armRawNEONMultiplyLongVector{}, false
	}
	destination := int(word>>12)&15 | int(word>>22&1)*16
	if destination&1 != 0 {
		return armRawNEONMultiplyLongVector{}, false
	}
	return armRawNEONMultiplyLongVector{
		kind:        kind,
		unsigned:    word>>24&1 != 0,
		elementBits: 8 << size,
		destination: destination,
		lhs:         int(word>>16)&15 | int(word>>7&1)*16,
		rhs:         int(word)&15 | int(word>>5&1)*16,
	}, true
}

func (c *armCtx) lowerRawNEONMultiplyLongVector(form armRawNEONMultiplyLongVector) error {
	narrowType := fmt.Sprintf("i%d", form.elementBits)
	wideType := fmt.Sprintf("i%d", form.elementBits*2)
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, form.elementBits, false, narrowType)
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, form.elementBits, false, narrowType)
	if err != nil {
		return err
	}
	extend := "sext"
	if form.unsigned {
		extend = "zext"
	}
	lhsWide := c.newTmp()
	rhsWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s to <%d x %s>\n",
		lhsWide, extend, lanes, narrowType, lhs, lanes, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s to <%d x %s>\n",
		rhsWide, extend, lanes, narrowType, rhs, lanes, wideType)
	return c.lowerARMRawNEONWideningProduct(
		form.kind, form.elementBits, form.destination, "%"+lhsWide, "%"+rhsWide,
	)
}
