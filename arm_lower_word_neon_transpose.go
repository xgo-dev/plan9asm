package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONTranspose struct {
	quad        bool
	elementBits int
	first       int
	second      int
}

// decodeARMRawNEONTranspose covers A32 VTRN.8/.16/.32 in D and Q registers.
// Both operand fields are read and written by the instruction.
func decodeARMRawNEONTranspose(word uint32) (armRawNEONTranspose, bool) {
	const variable = uint32(0x004cf06f)
	if word&^variable != 0xf3b20080 {
		return armRawNEONTranspose{}, false
	}
	size := int(word >> 18 & 3)
	if size == 3 {
		return armRawNEONTranspose{}, false
	}
	quad := word>>6&1 != 0
	first := int(word>>12)&15 | int(word>>22&1)*16
	second := int(word)&15 | int(word>>5&1)*16
	if quad && (first&1 != 0 || second&1 != 0) {
		return armRawNEONTranspose{}, false
	}
	return armRawNEONTranspose{
		quad:        quad,
		elementBits: 8 << size,
		first:       first,
		second:      second,
	}, true
}

func (c *armCtx) lowerRawNEONTranspose(form armRawNEONTranspose) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	first, lanes, err := c.loadARMRawNEONVector(
		form.first, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	second, _, err := c.loadARMRawNEONVector(
		form.second, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	firstIndices := make([]string, lanes)
	secondIndices := make([]string, lanes)
	for pair := 0; pair < lanes/2; pair++ {
		firstIndices[2*pair] = fmt.Sprintf("i32 %d", 2*pair)
		firstIndices[2*pair+1] = fmt.Sprintf("i32 %d", lanes+2*pair)
		secondIndices[2*pair] = fmt.Sprintf("i32 %d", 2*pair+1)
		secondIndices[2*pair+1] = fmt.Sprintf("i32 %d", lanes+2*pair+1)
	}
	firstResult := c.newTmp()
	secondResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %s, <%d x %s> %s, <%d x i32> <%s>\n",
		firstResult, lanes, elementType, first, lanes, elementType, second,
		lanes, strings.Join(firstIndices, ", "))
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %s, <%d x %s> %s, <%d x i32> <%s>\n",
		secondResult, lanes, elementType, first, lanes, elementType, second,
		lanes, strings.Join(secondIndices, ", "))
	if err := c.storeARMRawNEONVector(
		form.first, form.elementBits, form.quad, elementType, "%"+firstResult,
	); err != nil {
		return err
	}
	return c.storeARMRawNEONVector(
		form.second, form.elementBits, form.quad, elementType, "%"+secondResult,
	)
}
