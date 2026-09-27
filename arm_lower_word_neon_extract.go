package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONExtract struct {
	quad        bool
	destination int
	lhs         int
	rhs         int
	offset      int
}

// decodeARMRawNEONExtract covers A32 VEXT register forms. Element spellings
// of .8/.16/.32/.64 share the same byte-extract encoding; only the byte
// offset matters. D forms permit offsets 0..7 and Q forms 0..15.
func decodeARMRawNEONExtract(word uint32) (armRawNEONExtract, bool) {
	const variable = uint32(0x00400000 | 0x000f0000 | 0x0000f000 |
		0x00000f00 | 0x000000e0 | 0x0000000f)
	if word&^variable != 0xf2b00000 {
		return armRawNEONExtract{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	lhs := int(word>>16)&15 | int(word>>7&1)*16
	rhs := int(word)&15 | int(word>>5&1)*16
	offset := int(word >> 8 & 15)
	if !quad && offset >= 8 ||
		quad && (destination&1 != 0 || lhs&1 != 0 || rhs&1 != 0) {
		return armRawNEONExtract{}, false
	}
	return armRawNEONExtract{
		quad:        quad,
		destination: destination,
		lhs:         lhs,
		rhs:         rhs,
		offset:      offset,
	}, true
}

func (c *armCtx) lowerRawNEONExtract(form armRawNEONExtract) error {
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, 8, form.quad, "i8")
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, 8, form.quad, "i8")
	if err != nil {
		return err
	}
	indices := make([]string, lanes)
	for index := range indices {
		indices[index] = fmt.Sprintf("i32 %d", form.offset+index)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> <%s>\n",
		result, lanes, lhs, lanes, rhs, lanes, strings.Join(indices, ", "))
	return c.storeARMRawNEONVector(form.destination, 8, form.quad, "i8", "%"+result)
}
