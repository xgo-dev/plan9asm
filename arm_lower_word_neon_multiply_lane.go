package plan9asm

import "fmt"

type armRawNEONMultiplyLane struct {
	floating    bool
	quad        bool
	elementBits int
	destination int
	lhs         int
	scalar      int
	lane        int
}

// decodeARMRawNEONMultiplyLane covers every LLVM 22 ARMInstrNEON VMUL scalar
// lane form: integer i16/i32 and floating f16/f32, D and Q destinations. The
// 16-bit encoding addresses D0..D7 with four lanes; the 32-bit encoding
// addresses D0..D15 with two lanes.
func decodeARMRawNEONMultiplyLane(word uint32) (armRawNEONMultiplyLane, bool) {
	if word&0xfe800e50 != 0xf2800840 {
		return armRawNEONMultiplyLane{}, false
	}
	elementBits := 0
	switch word >> 20 & 3 {
	case 1:
		elementBits = 16
	case 2:
		elementBits = 32
	default:
		return armRawNEONMultiplyLane{}, false
	}
	quad := word>>24&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	lhs := int(word>>16)&15 | int(word>>7&1)*16
	if quad && (destination&1 != 0 || lhs&1 != 0) {
		return armRawNEONMultiplyLane{}, false
	}
	scalar := int(word) & 15
	lane := int(word>>5) & 1
	if elementBits == 16 {
		scalar &= 7
		lane = int(word>>3)&1 | int(word>>5&1)*2
	}
	return armRawNEONMultiplyLane{
		floating:    word>>8&1 != 0,
		quad:        quad,
		elementBits: elementBits,
		destination: destination,
		lhs:         lhs,
		scalar:      scalar,
		lane:        lane,
	}, true
}

func (c *armCtx) lowerRawNEONMultiplyLane(form armRawNEONMultiplyLane) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	operation := "mul"
	if form.floating {
		elementType = "half"
		if form.elementBits == 32 {
			elementType = "float"
		}
		operation = "fmul"
	}
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, form.elementBits, form.quad, elementType)
	if err != nil {
		return err
	}
	scalars, scalarLanes, err := c.loadARMRawNEONVector(form.scalar, form.elementBits, false, elementType)
	if err != nil {
		return err
	}
	scalar := c.newTmp()
	inserted := c.newTmp()
	broadcast := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", scalar, scalarLanes, elementType, scalars, form.lane)
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> poison, %s %%%s, i32 0\n", inserted, lanes, elementType, elementType, scalar)
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> poison, <%d x i32> zeroinitializer\n", broadcast, lanes, elementType, inserted, lanes, elementType, lanes)
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s, %%%s\n", result, operation, lanes, elementType, lhs, broadcast)
	return c.storeARMRawNEONVector(form.destination, form.elementBits, form.quad, elementType, "%"+result)
}
