package plan9asm

import "fmt"

type armRawNEONAddSub struct {
	subtract    bool
	floating    bool
	quad        bool
	elementBits int
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawNEONAddSub covers A32 Advanced SIMD VADD/VSUB register forms:
// integer elements of 8, 16, 32, or 64 bits and floating elements of 16 or
// 32 bits, each in both D and Q registers.
func decodeARMRawNEONAddSub(word uint32) (armRawNEONAddSub, bool) {
	const variable = uint32(0x00400000 | 0x00300000 | 0x000f0000 |
		0x0000f000 | 0x000000e0 | 0x0000000f)
	var floating, subtract bool
	switch word &^ variable {
	case 0xf2000800:
	case 0xf3000800:
		subtract = true
	case 0xf2000d00:
		floating = true
		subtract = word>>21&1 != 0
	default:
		return armRawNEONAddSub{}, false
	}
	encodedSize := int(word >> 20 & 3)
	elementBits := 8 << encodedSize
	if floating {
		elementBits = 32
		if encodedSize&1 != 0 {
			elementBits = 16
		}
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	lhs := int(word>>16)&15 | int(word>>7&1)*16
	rhs := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || lhs&1 != 0 || rhs&1 != 0) {
		return armRawNEONAddSub{}, false
	}
	return armRawNEONAddSub{
		subtract:    subtract,
		floating:    floating,
		quad:        quad,
		elementBits: elementBits,
		destination: destination,
		lhs:         lhs,
		rhs:         rhs,
	}, true
}

func (c *armCtx) lowerRawNEONAddSub(form armRawNEONAddSub) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	operation := "add"
	if form.subtract {
		operation = "sub"
	}
	if form.floating {
		elementType = "half"
		if form.elementBits == 32 {
			elementType = "float"
		}
		operation = "f" + operation
	}
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, form.elementBits, form.quad, elementType)
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, form.elementBits, form.quad, elementType)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s, %s\n",
		result, operation, lanes, elementType, lhs, rhs)
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}
