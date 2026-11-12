package plan9asm

import "fmt"

type arm64RawFMULByElement struct {
	vector      bool
	extended    bool
	arrangement arm64VectorArrangement
	lane        int
	elementReg  int
	sourceReg   int
	destination int
}

func decodeARM64RawFMULByElement(word uint32) (arm64RawFMULByElement, bool) {
	scalarHalf := word&0xdfc0f400 == 0x5f009000
	vectorHalf := word&0x9fc0f400 == 0x0f009000
	scalar := scalarHalf || word&0xdf80f400 == 0x5f809000
	vector := vectorHalf || word&0x9f80f400 == 0x0f809000
	if !scalar && !vector {
		return arm64RawFMULByElement{}, false
	}

	elementBits := 16
	if !scalarHalf && !vectorHalf {
		elementBits = 32
	}
	if elementBits == 32 && word&(1<<22) != 0 {
		elementBits = 64
	}
	// The L bit is part of the lane index for S elements, but is reserved for
	// D elements. The vector encoding also reserves its 64-bit D1 combination.
	if elementBits == 64 && word&(1<<21) != 0 {
		return arm64RawFMULByElement{}, false
	}
	vectorBits := elementBits
	if vector {
		vectorBits = 64
		if word&(1<<30) != 0 {
			vectorBits = 128
		}
		if elementBits == 64 && vectorBits == 64 {
			return arm64RawFMULByElement{}, false
		}
	}
	lane := int(word>>11) & 1
	if elementBits == 16 {
		lane = lane<<2 | (int(word>>21)&1)<<1 | int(word>>20)&1
	} else if elementBits == 32 {
		lane = lane<<1 | int(word>>21)&1
	}
	elementReg := int(word>>16) & 31
	if elementBits == 16 {
		elementReg &= 15
	}
	return arm64RawFMULByElement{
		vector:      vector,
		extended:    word&(1<<29) != 0,
		arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
		lane:        lane,
		elementReg:  elementReg,
		sourceReg:   int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFMULByElement(form arm64RawFMULByElement) error {
	bits := form.arrangement.elementBits
	floatType := "float"
	if bits == 16 {
		floatType = "half"
	} else if bits == 64 {
		floatType = "double"
	}
	elementBytes, err := c.loadVReg(Reg(fmt.Sprintf("V%d", form.elementReg)))
	if err != nil {
		return err
	}
	physicalLanes := 128 / bits
	typedElements := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x %s>\n", typedElements, elementBytes, physicalLanes, floatType)
	element := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %%%s, i32 %d\n", element, physicalLanes, floatType, typedElements, form.lane)

	if !form.vector {
		sourceReg := Reg(fmt.Sprintf("F%d", form.sourceReg))
		destinationReg := Reg(fmt.Sprintf("F%d", form.destination))
		source, err := c.loadARM64ScalarFloatReg(sourceReg, bits)
		if err != nil {
			return err
		}
		result := c.newTmp()
		if form.extended {
			suffix := fmt.Sprintf("f%d", bits)
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.fmulx.%s(%s %s, %s %%%s)\n",
				result, floatType, suffix, floatType, source, floatType, element)
		} else {
			fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %%%s\n", result, floatType, source, element)
		}
		return c.storeARM64ScalarFloatReg(destinationReg, bits, "%"+result)
	}

	arrangementName := arm64VectorArrangementName(form.arrangement)
	sourceReg := Reg(fmt.Sprintf("V%d.%s", form.sourceReg, arrangementName))
	destinationReg := Reg(fmt.Sprintf("V%d.%s", form.destination, arrangementName))
	source, err := c.loadARM64VectorFloat(sourceReg, form.arrangement)
	if err != nil {
		return err
	}
	seed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> poison, %s %%%s, i32 0\n", seed, form.arrangement.lanes, floatType, floatType, element)
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> poison, <%d x i32> zeroinitializer\n",
		splat, form.arrangement.lanes, floatType, seed, form.arrangement.lanes, floatType, form.arrangement.lanes)
	result := c.newTmp()
	if form.extended {
		fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.aarch64.neon.fmulx.v%df%d(<%d x %s> %s, <%d x %s> %%%s)\n",
			result, form.arrangement.lanes, floatType, form.arrangement.lanes, bits,
			form.arrangement.lanes, floatType, source, form.arrangement.lanes, floatType, splat)
	} else {
		fmt.Fprintf(c.b, "  %%%s = fmul <%d x %s> %s, %%%s\n", result, form.arrangement.lanes, floatType, source, splat)
	}
	return c.storeARM64VectorFloat(destinationReg, form.arrangement, "%"+result)
}
