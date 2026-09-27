package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONShiftInsert struct {
	left        bool
	quad        bool
	elementBits int
	shift       int
	destination int
	source      int
}

// decodeARMRawNEONShiftInsert covers A32 VSLI and VSRI immediate forms for
// 8-, 16-, 32-, and 64-bit elements, both D/Q widths, and every legal shift.
func decodeARMRawNEONShiftInsert(word uint32) (armRawNEONShiftInsert, bool) {
	const variable = uint32(0x007ff0ef)
	left := false
	switch word &^ variable {
	case 0xf3800510:
		left = true
	case 0xf3800410:
	default:
		return armRawNEONShiftInsert{}, false
	}
	imm7 := int(word>>16&0x3f) | int(word>>7&1)<<6
	if imm7 < 8 {
		return armRawNEONShiftInsert{}, false
	}
	elementBits := 8
	for elementBits*2 <= imm7 {
		elementBits *= 2
	}
	shift := imm7 - elementBits
	if !left {
		shift = 2*elementBits - imm7
	}
	if left && (shift < 0 || shift >= elementBits) ||
		!left && (shift < 1 || shift > elementBits) {
		return armRawNEONShiftInsert{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONShiftInsert{}, false
	}
	return armRawNEONShiftInsert{
		left:        left,
		quad:        quad,
		elementBits: elementBits,
		shift:       shift,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONShiftInsert(form armRawNEONShiftInsert) error {
	if !form.left && form.shift == form.elementBits {
		return nil
	}
	elementType := fmt.Sprintf("i%d", form.elementBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	destination, _, err := c.loadARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	operation := "lshr"
	mask := ^uint64(0) << (form.elementBits - form.shift)
	if form.left {
		operation = "shl"
		mask = uint64(1)<<form.shift - 1
	}
	if form.elementBits < 64 {
		mask &= uint64(1)<<form.elementBits - 1
	}
	counts := make([]string, lanes)
	masks := make([]string, lanes)
	for index := range counts {
		counts[index] = fmt.Sprintf("%s %d", elementType, form.shift)
		masks[index] = fmt.Sprintf("%s %d", elementType, int64(mask))
	}
	shifted := c.newTmp()
	kept := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s, <%s>\n",
		shifted, operation, lanes, elementType, source, strings.Join(counts, ", "))
	fmt.Fprintf(c.b, "  %%%s = and <%d x %s> %s, <%s>\n",
		kept, lanes, elementType, destination, strings.Join(masks, ", "))
	fmt.Fprintf(c.b, "  %%%s = or <%d x %s> %%%s, %%%s\n",
		result, lanes, elementType, kept, shifted)
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}
