package plan9asm

import "fmt"

type arm64RawPairwiseAddLong struct {
	signed      bool
	accumulate  bool
	source      arm64VectorArrangement
	destination arm64VectorArrangement
	sourceReg   int
	destReg     int
}

func decodeARM64RawPairwiseAddLong(word uint32) (arm64RawPairwiseAddLong, bool) {
	form := arm64RawPairwiseAddLong{}
	switch word & 0xbf3ffc00 {
	case 0x0e202800: // SADDLP.
		form.signed = true
	case 0x2e202800: // UADDLP.
	case 0x0e206800: // SADALP.
		form.signed, form.accumulate = true, true
	case 0x2e206800: // UADALP.
		form.accumulate = true
	default:
		return arm64RawPairwiseAddLong{}, false
	}
	size := int(word>>22) & 3
	if size > 2 {
		return arm64RawPairwiseAddLong{}, false
	}
	sourceBits := 8 << size
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	sourceLanes := vectorBits / sourceBits
	form.source = arm64VectorArrangement{elementBits: sourceBits, lanes: sourceLanes}
	form.destination = arm64VectorArrangement{elementBits: sourceBits * 2, lanes: sourceLanes / 2}
	form.sourceReg = int(word>>5) & 31
	form.destReg = int(word & 31)
	return form, true
}

// Keep the instruction-specific entry point for focused compatibility tests.
type arm64RawUADALP = arm64RawPairwiseAddLong

func decodeARM64RawUADALP(word uint32) (arm64RawUADALP, bool) {
	form, ok := decodeARM64RawPairwiseAddLong(word)
	if !ok || form.signed || !form.accumulate {
		return arm64RawUADALP{}, false
	}
	return form, true
}

func (c *arm64Ctx) lowerRawUADALP(form arm64RawUADALP) error {
	return c.lowerRawPairwiseAddLong(form)
}

func (c *arm64Ctx) lowerRawPairwiseAddLong(form arm64RawPairwiseAddLong) error {
	source, err := c.loadRawARM64VectorOperand(form.sourceReg, form.source, 0, false)
	if err != nil {
		return err
	}
	sourceType := fmt.Sprintf("<%d x i%d>", form.source.lanes, form.source.elementBits)
	pairType := fmt.Sprintf("<%d x i%d>", form.destination.lanes, form.source.elementBits)
	destType := fmt.Sprintf("<%d x i%d>", form.destination.lanes, form.destination.elementBits)
	even := c.newTmp()
	odd := c.newTmp()
	c.writeRawPairwiseAddLongShuffle(even, sourceType, source, pairType, form.destination.lanes, 0)
	c.writeRawPairwiseAddLongShuffle(odd, sourceType, source, pairType, form.destination.lanes, 1)
	wideEven := c.newTmp()
	wideOdd := c.newTmp()
	pairs := c.newTmp()
	extension := "zext"
	if form.signed {
		extension = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", wideEven, extension, pairType, even, destType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", wideOdd, extension, pairType, odd, destType)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", pairs, destType, wideEven, wideOdd)
	result := "%" + pairs
	if form.accumulate {
		accumulator, err := c.loadRawARM64VectorOperand(form.destReg, form.destination, 0, false)
		if err != nil {
			return err
		}
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", added, destType, accumulator, pairs)
		result = "%" + added
	}
	return c.storeRawARM64VectorResult(form.destReg, form.destination, result, false)
}

func (c *arm64Ctx) writeRawPairwiseAddLongShuffle(name, sourceType, source, resultType string, lanes, parity int) {
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <", name, sourceType, source, sourceType, lanes)
	for lane := 0; lane < lanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", lane*2+parity)
	}
	c.b.WriteString(">\n")
}
