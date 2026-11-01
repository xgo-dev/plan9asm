package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONBitClearImmediate struct {
	quad        bool
	elementBits int
	shift       int
	destination int
	imm8        int
}

// decodeARMRawNEONBitClearImmediate covers all A32 VBIC modified-immediate
// forms accepted by LLVM 22: i16 byte positions 0/8 and i32 byte positions
// 0/8/16/24, with every imm8 value and D/Q destination register.
func decodeARMRawNEONBitClearImmediate(word uint32) (armRawNEONBitClearImmediate, bool) {
	const variable = uint32(0x01000000 | 0x00400000 | 0x00070000 |
		0x0000f000 | 0x00000f00 | 0x00000040 | 0x0000000f)
	if word&^variable != 0xf2800030 {
		return armRawNEONBitClearImmediate{}, false
	}
	cmode := int(word >> 8 & 15)
	elementBits := 32
	shift := 0
	switch cmode {
	case 1, 3, 5, 7:
		shift = (cmode - 1) / 2 * 8
	case 9, 11:
		elementBits = 16
		shift = (cmode - 9) / 2 * 8
	default:
		return armRawNEONBitClearImmediate{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	if quad && destination&1 != 0 {
		return armRawNEONBitClearImmediate{}, false
	}
	return armRawNEONBitClearImmediate{
		quad:        quad,
		elementBits: elementBits,
		shift:       shift,
		destination: destination,
		imm8:        int(word>>24&1)*128 | int(word>>16&7)*16 | int(word&15),
	}, true
}

func (c *armCtx) lowerRawNEONBitClearImmediate(form armRawNEONBitClearImmediate) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	destination, lanes, err := c.loadARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType,
	)
	if err != nil {
		return err
	}
	widthMask := uint64(1)<<form.elementBits - 1
	clearMask := widthMask &^ (uint64(form.imm8) << form.shift)
	constants := make([]string, lanes)
	for index := range constants {
		constants[index] = fmt.Sprintf("%s %d", elementType, clearMask)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and <%d x %s> %s, <%s>\n",
		result, lanes, elementType, destination, strings.Join(constants, ", "))
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType, "%"+result,
	)
}
