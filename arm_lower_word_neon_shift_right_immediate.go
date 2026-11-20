package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONShiftRightImmediate struct {
	unsigned    bool
	quad        bool
	elementBits int
	shift       int
	destination int
	source      int
}

// decodeARMRawNEONShiftRightImmediate covers A32 VSHR.S/U immediate forms
// for 8-, 16-, 32-, and 64-bit elements in D and Q registers. The immediate
// range includes a full-element shift, whose unsigned result is zero.
func decodeARMRawNEONShiftRightImmediate(word uint32) (armRawNEONShiftRightImmediate, bool) {
	const variable = uint32(0x017ff0ef)
	const base = uint32(0xf2800010)
	if word&^variable != base {
		return armRawNEONShiftRightImmediate{}, false
	}
	imm7 := int(word>>16&0x3f) | int(word>>7&1)<<6
	if imm7 < 8 {
		return armRawNEONShiftRightImmediate{}, false
	}
	elementBits := 8
	for elementBits*2 <= imm7 {
		elementBits *= 2
	}
	shift := 2*elementBits - imm7
	if shift < 1 || shift > elementBits {
		return armRawNEONShiftRightImmediate{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONShiftRightImmediate{}, false
	}
	return armRawNEONShiftRightImmediate{
		unsigned:    word>>24&1 != 0,
		quad:        quad,
		elementBits: elementBits,
		shift:       shift,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONShiftRightImmediate(form armRawNEONShiftRightImmediate) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	if form.unsigned && form.shift == form.elementBits {
		return c.storeARMRawNEONVector(
			form.destination, form.elementBits, form.quad, elementType, "zeroinitializer",
		)
	}
	operation := "ashr"
	if form.unsigned {
		operation = "lshr"
	}
	shift := form.shift
	if shift == form.elementBits {
		shift--
	}
	counts := make([]string, lanes)
	for index := range counts {
		counts[index] = fmt.Sprintf("%s %d", elementType, shift)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s, <%s>\n",
		result, operation, lanes, elementType, source, strings.Join(counts, ", "))
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}
