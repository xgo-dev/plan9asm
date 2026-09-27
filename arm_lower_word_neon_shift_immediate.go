package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONShiftImmediate struct {
	elementBits int
	shift       int
	quad        bool
	destination int
	source      int
}

// Classic A32 VSHL immediate has one D/Q encoding for each 8-, 16-, 32-,
// and 64-bit element width. The highest set bit of imm7 selects the width;
// the remaining bits are the immediate shift. Signed and unsigned spellings
// have identical left-shift semantics and the same encoding.
func decodeARMRawNEONShiftImmediate(word uint32) (armRawNEONShiftImmediate, bool) {
	const variable = uint32(0x007ff0ef)
	const base = uint32(0xf2800510)
	if word&^variable != base {
		return armRawNEONShiftImmediate{}, false
	}
	imm7 := int(word>>16&0x3f) | int(word>>7&1)<<6
	if imm7 < 8 {
		return armRawNEONShiftImmediate{}, false
	}
	elementBits := 8
	for elementBits*2 <= imm7 {
		elementBits *= 2
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONShiftImmediate{}, false
	}
	return armRawNEONShiftImmediate{
		elementBits: elementBits,
		shift:       imm7 - elementBits,
		quad:        quad,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONShiftImmediate(form armRawNEONShiftImmediate) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	counts := make([]string, lanes)
	for index := range counts {
		counts[index] = fmt.Sprintf("%s %d", elementType, form.shift)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl <%d x %s> %s, <%s>\n",
		result, lanes, elementType, source, strings.Join(counts, ", "))
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}
