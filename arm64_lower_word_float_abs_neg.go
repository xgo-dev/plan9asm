package plan9asm

import "fmt"

type arm64RawFloatAbsNeg struct {
	negate      bool
	arrangement arm64VectorArrangement
	source      int
	destination int
}

// decodeARM64RawFloatAbsNeg recognizes the FP16 Advanced SIMD forms that Go's
// named VFABS/VFNEG optab cannot express. S2/S4/D2 WORD encodings are decoded
// by x/arch and flow through the complete named-form lowerer.
func decodeARM64RawFloatAbsNeg(word uint32) (arm64RawFloatAbsNeg, bool) {
	const registers = uint32(31 | 31<<5)
	key := word &^ registers
	negate := false
	switch key {
	case 0x0ef8f800, 0x4ef8f800:
	case 0x2ef8f800, 0x6ef8f800:
		negate = true
	default:
		return arm64RawFloatAbsNeg{}, false
	}
	lanes := 4
	if word&(1<<30) != 0 {
		lanes = 8
	}
	return arm64RawFloatAbsNeg{
		negate:      negate,
		arrangement: arm64VectorArrangement{elementBits: 16, lanes: lanes},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFloatAbsNeg(form arm64RawFloatAbsNeg) error {
	source, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.source)), form.arrangement)
	if err != nil {
		return err
	}
	result := c.newTmp()
	vectorType := fmt.Sprintf("<%d x half>", form.arrangement.lanes)
	if form.negate {
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", result, vectorType, source)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.v%df16(%s %s)\n", result, vectorType, form.arrangement.lanes, vectorType, source)
	}
	return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), form.arrangement, "%"+result)
}
