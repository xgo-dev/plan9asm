package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONShiftRightNarrow struct {
	sourceBits  int
	shift       int
	destination int
	source      int
}

// decodeARMRawNEONShiftRightNarrow covers all non-saturating A32 VSHRN
// immediate forms: i16-to-i8, i32-to-i16, and i64-to-i32, with shifts 1
// through the destination element width and all D/Q register fields.
func decodeARMRawNEONShiftRightNarrow(word uint32) (armRawNEONShiftRightNarrow, bool) {
	const variable = uint32(0x007ff02f)
	if word&^variable != 0xf2800810 {
		return armRawNEONShiftRightNarrow{}, false
	}
	imm6 := int(word >> 16 & 0x3f)
	if imm6 < 8 {
		return armRawNEONShiftRightNarrow{}, false
	}
	resultBits := 8
	for resultBits*2 <= imm6 {
		resultBits *= 2
	}
	if resultBits > 32 {
		return armRawNEONShiftRightNarrow{}, false
	}
	sourceBits := resultBits * 2
	shift := sourceBits - imm6
	if shift < 1 || shift > resultBits {
		return armRawNEONShiftRightNarrow{}, false
	}
	source := int(word)&15 | int(word>>5&1)*16
	if source&1 != 0 {
		return armRawNEONShiftRightNarrow{}, false
	}
	return armRawNEONShiftRightNarrow{
		sourceBits:  sourceBits,
		shift:       shift,
		destination: int(word>>12)&15 | int(word>>22&1)*16,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONShiftRightNarrow(form armRawNEONShiftRightNarrow) error {
	sourceType := fmt.Sprintf("i%d", form.sourceBits)
	resultBits := form.sourceBits / 2
	resultType := fmt.Sprintf("i%d", resultBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.sourceBits, true, sourceType,
	)
	if err != nil {
		return err
	}
	counts := make([]string, lanes)
	for index := range counts {
		counts[index] = fmt.Sprintf("%s %d", sourceType, form.shift)
	}
	shifted := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr <%d x %s> %s, <%s>\n",
		shifted, lanes, sourceType, source, strings.Join(counts, ", "))
	fmt.Fprintf(c.b, "  %%%s = trunc <%d x %s> %%%s to <%d x %s>\n",
		result, lanes, sourceType, shifted, lanes, resultType)
	return c.storeARMRawNEONVector(
		form.destination, resultBits, false, resultType, "%"+result,
	)
}
