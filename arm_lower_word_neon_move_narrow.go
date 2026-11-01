package plan9asm

import "fmt"

type armRawNEONMoveNarrow struct {
	sourceBits  int
	destination int
	source      int
}

// decodeARMRawNEONMoveNarrow covers every non-saturating A32 VMOVN register
// form: 16-to-8, 32-to-16, and 64-to-32 narrowing from Q to D.
func decodeARMRawNEONMoveNarrow(word uint32) (armRawNEONMoveNarrow, bool) {
	const variable = uint32(0x004cf02f)
	if word&^variable != 0xf3b20200 {
		return armRawNEONMoveNarrow{}, false
	}
	size := int(word >> 18 & 3)
	if size == 3 {
		return armRawNEONMoveNarrow{}, false
	}
	source := int(word)&15 | int(word>>5&1)*16
	if source&1 != 0 {
		return armRawNEONMoveNarrow{}, false
	}
	return armRawNEONMoveNarrow{
		sourceBits:  16 << size,
		destination: int(word>>12)&15 | int(word>>22&1)*16,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONMoveNarrow(form armRawNEONMoveNarrow) error {
	sourceType := fmt.Sprintf("i%d", form.sourceBits)
	resultBits := form.sourceBits / 2
	resultType := fmt.Sprintf("i%d", resultBits)
	source, lanes, err := c.loadARMRawNEONVector(
		form.source, form.sourceBits, true, sourceType,
	)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc <%d x %s> %s to <%d x %s>\n",
		result, lanes, sourceType, source, lanes, resultType)
	return c.storeARMRawNEONVector(
		form.destination, resultBits, false, resultType, "%"+result,
	)
}
