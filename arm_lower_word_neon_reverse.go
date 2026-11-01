package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONReverse struct {
	blockBits   int
	elementBits int
	quad        bool
	destination int
	source      int
}

// decodeARMRawNEONReverse covers A32 VREV16.8, VREV32.8/.16, and
// VREV64.8/.16/.32 for both D and Q registers. Invalid equal-width and
// reserved register encodings are rejected.
func decodeARMRawNEONReverse(word uint32) (armRawNEONReverse, bool) {
	const variable = uint32(0x00400000 | 0x000c0000 | 0x0000f000 |
		0x00000180 | 0x00000060 | 0x0000000f)
	if word&^variable != 0xf3b00000 {
		return armRawNEONReverse{}, false
	}
	blockBits := 64
	switch word >> 7 & 3 {
	case 1:
		blockBits = 32
	case 2:
		blockBits = 16
	case 3:
		return armRawNEONReverse{}, false
	}
	elementBits := 8 << (word >> 18 & 3)
	if elementBits >= blockBits {
		return armRawNEONReverse{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONReverse{}, false
	}
	return armRawNEONReverse{
		blockBits:   blockBits,
		elementBits: elementBits,
		quad:        quad,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONReverse(form armRawNEONReverse) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	blockLanes := form.blockBits / form.elementBits
	indices := make([]string, lanes)
	for lane := range indices {
		blockStart := lane / blockLanes * blockLanes
		index := blockStart + blockLanes - 1 - lane%blockLanes
		indices[lane] = fmt.Sprintf("i32 %d", index)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b,
		"  %%%s = shufflevector <%d x %s> %s, <%d x %s> poison, <%d x i32> <%s>\n",
		result, lanes, elementType, source, lanes, elementType, lanes, strings.Join(indices, ", "),
	)
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}
