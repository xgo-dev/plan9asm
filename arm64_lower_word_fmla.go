package plan9asm

import "fmt"

type arm64RawFMLA struct {
	subtract    bool
	indexed     bool
	scalar      bool
	arrangement arm64VectorArrangement
	lane        int
	elementReg  int
	sourceReg   int
	destination int
}

type arm64RawFMLAIndexedFormat struct {
	base        uint32
	subtract    bool
	scalar      bool
	elementBits int
	vectorBits  int
}

var arm64RawFMLAIndexedFormats = [...]arm64RawFMLAIndexedFormat{
	{base: 0x5f001000, scalar: true, elementBits: 16, vectorBits: 16},
	{base: 0x5f005000, subtract: true, scalar: true, elementBits: 16, vectorBits: 16},
	{base: 0x5f801000, scalar: true, elementBits: 32, vectorBits: 32},
	{base: 0x5f805000, subtract: true, scalar: true, elementBits: 32, vectorBits: 32},
	{base: 0x5fc01000, scalar: true, elementBits: 64, vectorBits: 64},
	{base: 0x5fc05000, subtract: true, scalar: true, elementBits: 64, vectorBits: 64},
	{base: 0x0f001000, elementBits: 16, vectorBits: 64},
	{base: 0x0f005000, subtract: true, elementBits: 16, vectorBits: 64},
	{base: 0x4f001000, elementBits: 16, vectorBits: 128},
	{base: 0x4f005000, subtract: true, elementBits: 16, vectorBits: 128},
	{base: 0x0f801000, elementBits: 32, vectorBits: 64},
	{base: 0x0f805000, subtract: true, elementBits: 32, vectorBits: 64},
	{base: 0x4f801000, elementBits: 32, vectorBits: 128},
	{base: 0x4f805000, subtract: true, elementBits: 32, vectorBits: 128},
	{base: 0x4fc01000, elementBits: 64, vectorBits: 128},
	{base: 0x4fc05000, subtract: true, elementBits: 64, vectorBits: 128},
}

func decodeARM64RawFMLA(word uint32) (arm64RawFMLA, bool) {
	const vectorRegisters = uint32(31 | 31<<5 | 31<<16)
	form := arm64RawFMLA{}
	switch word &^ vectorRegisters {
	case 0x0e400c00:
		form.arrangement = arm64VectorArrangement{elementBits: 16, lanes: 4}
	case 0x4e400c00:
		form.arrangement = arm64VectorArrangement{elementBits: 16, lanes: 8}
	case 0x0e20cc00:
		form.arrangement = arm64VectorArrangement{elementBits: 32, lanes: 2}
	case 0x4e20cc00:
		form.arrangement = arm64VectorArrangement{elementBits: 32, lanes: 4}
	case 0x4e60cc00:
		form.arrangement = arm64VectorArrangement{elementBits: 64, lanes: 2}
	case 0x0ec00c00:
		form.subtract, form.arrangement = true, arm64VectorArrangement{elementBits: 16, lanes: 4}
	case 0x4ec00c00:
		form.subtract, form.arrangement = true, arm64VectorArrangement{elementBits: 16, lanes: 8}
	case 0x0ea0cc00:
		form.subtract, form.arrangement = true, arm64VectorArrangement{elementBits: 32, lanes: 2}
	case 0x4ea0cc00:
		form.subtract, form.arrangement = true, arm64VectorArrangement{elementBits: 32, lanes: 4}
	case 0x4ee0cc00:
		form.subtract, form.arrangement = true, arm64VectorArrangement{elementBits: 64, lanes: 2}
	}
	if form.arrangement.elementBits != 0 {
		form.elementReg = int(word>>16) & 31
		form.sourceReg = int(word>>5) & 31
		form.destination = int(word) & 31
		form.lane = -1
		return form, true
	}

	for _, format := range arm64RawFMLAIndexedFormats {
		variable := uint32(31 | 31<<5 | 31<<16 | 1<<11)
		if format.elementBits == 16 {
			variable = uint32(31 | 31<<5 | 15<<16 | 1<<20 | 1<<21 | 1<<11)
		} else if format.elementBits == 32 {
			variable |= 1 << 21
		}
		if word&^variable != format.base {
			continue
		}
		lane := int(word>>11) & 1
		elementReg := int(word>>16) & 31
		if format.elementBits == 16 {
			lane = lane<<2 | (int(word>>21)&1)<<1 | int(word>>20)&1
			elementReg &= 15
		} else if format.elementBits == 32 {
			lane = lane<<1 | int(word>>21)&1
		}
		return arm64RawFMLA{
			subtract:    format.subtract,
			indexed:     true,
			scalar:      format.scalar,
			arrangement: arm64VectorArrangement{elementBits: format.elementBits, lanes: format.vectorBits / format.elementBits},
			lane:        lane,
			elementReg:  elementReg,
			sourceReg:   int(word>>5) & 31,
			destination: int(word) & 31,
		}, true
	}
	return arm64RawFMLA{}, false
}

func (c *arm64Ctx) lowerRawFMLA(form arm64RawFMLA) error {
	bits := form.arrangement.elementBits
	floatType := arm64RawFloatType(bits)
	sourceReg := Reg(fmt.Sprintf("V%d", form.sourceReg))
	destinationReg := Reg(fmt.Sprintf("V%d", form.destination))
	var source, accumulator string
	var err error
	if form.scalar {
		source, err = c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.sourceReg)), bits)
		if err == nil {
			accumulator, err = c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.destination)), bits)
		}
	} else {
		source, err = c.loadARM64VectorFloat(sourceReg, form.arrangement)
		if err == nil {
			accumulator, err = c.loadARM64VectorFloat(destinationReg, form.arrangement)
		}
	}
	if err != nil {
		return err
	}

	multiplier := ""
	if form.indexed {
		elementBytes, err := c.loadVReg(Reg(fmt.Sprintf("V%d", form.elementReg)))
		if err != nil {
			return err
		}
		physicalLanes := 128 / bits
		typedElements := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x %s>\n", typedElements, elementBytes, physicalLanes, floatType)
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %%%s, i32 %d\n", element, physicalLanes, floatType, typedElements, form.lane)
		multiplier = "%" + element
		if !form.scalar {
			seed := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> poison, %s %s, i32 0\n",
				seed, form.arrangement.lanes, floatType, floatType, multiplier)
			splat := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> poison, <%d x i32> zeroinitializer\n",
				splat, form.arrangement.lanes, floatType, seed, form.arrangement.lanes, floatType, form.arrangement.lanes)
			multiplier = "%" + splat
		}
	} else {
		multiplier, err = c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.elementReg)), form.arrangement)
		if err != nil {
			return err
		}
	}

	if form.subtract {
		negated := c.newTmp()
		if form.scalar {
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negated, floatType, source)
		} else {
			fmt.Fprintf(c.b, "  %%%s = fneg <%d x %s> %s\n", negated, form.arrangement.lanes, floatType, source)
		}
		source = "%" + negated
	}
	result := c.newTmp()
	if form.scalar {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.f%d(%s %s, %s %s, %s %s)\n",
			result, floatType, bits, floatType, source, floatType, multiplier, floatType, accumulator)
		return c.storeARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.destination)), bits, "%"+result)
	}
	vectorType := fmt.Sprintf("<%d x %s>", form.arrangement.lanes, floatType)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.v%df%d(%s %s, %s %s, %s %s)\n",
		result, vectorType, form.arrangement.lanes, bits,
		vectorType, source, vectorType, multiplier, vectorType, accumulator)
	return c.storeARM64VectorFloat(destinationReg, form.arrangement, "%"+result)
}
