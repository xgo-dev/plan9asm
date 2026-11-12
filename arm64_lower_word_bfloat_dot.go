package plan9asm

import "fmt"

// arm64RawBFloatDot covers the two Advanced SIMD BFDOT encodings: vector and
// by-element. Both accept 64- and 128-bit arrangements. The indexed form
// selects one of four BF16 pairs from any source V register.
type arm64RawBFloatDot struct {
	indexed     bool
	lane        int
	lanes       int
	destination int
	left        int
	right       int
}

func decodeARM64RawBFloatDot(word uint32) (arm64RawBFloatDot, bool) {
	form := arm64RawBFloatDot{lane: 0}
	switch {
	case word&0xbfe0fc00 == 0x2e40fc00: // BFDOT (vector).
	case word&0xbfc0f400 == 0x0f40f000: // BFDOT (by element).
		form.indexed = true
		form.lane = int(word>>21)&1 | int(word>>10)&2
	default:
		return arm64RawBFloatDot{}, false
	}
	form.lanes = 2
	if word&(1<<30) != 0 {
		form.lanes = 4
	}
	form.destination = int(word) & 31
	form.left = int(word>>5) & 31
	form.right = int(word>>16) & 31
	return form, true
}

func (c *arm64Ctx) lowerRawBFloatDot(form arm64RawBFloatDot) error {
	accumulatorArrangement := arm64VectorArrangement{elementBits: 32, lanes: form.lanes}
	inputArrangement := arm64VectorArrangement{elementBits: 16, lanes: form.lanes * 2}
	accumulatorReg := Reg(fmt.Sprintf("V%d", form.destination))

	accumulator, err := c.loadARM64VectorFloat(accumulatorReg, accumulatorArrangement)
	if err != nil {
		return err
	}
	left, err := c.loadARM64VectorInteger(Reg(fmt.Sprintf("V%d", form.left)), inputArrangement)
	if err != nil {
		return err
	}
	leftBFloat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x bfloat>\n",
		leftBFloat, inputArrangement.lanes, left, inputArrangement.lanes)

	rightArrangement := inputArrangement
	if form.indexed {
		rightArrangement.lanes = 8
	}
	right, err := c.loadARM64VectorInteger(Reg(fmt.Sprintf("V%d", form.right)), rightArrangement)
	if err != nil {
		return err
	}
	rightBFloat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x bfloat>\n",
		rightBFloat, rightArrangement.lanes, right, rightArrangement.lanes)
	rightValue := "%" + rightBFloat
	if form.indexed {
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x bfloat> %s, <8 x bfloat> poison, <%d x i32> <",
			selected, rightValue, inputArrangement.lanes)
		for i := 0; i < inputArrangement.lanes; i++ {
			if i != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", form.lane*2+i%2)
		}
		c.b.WriteString(">\n")
		rightValue = "%" + selected
	}

	result := c.newTmp()
	fmt.Fprintf(c.b,
		"  %%%s = call <%d x float> @llvm.aarch64.neon.bfdot.v%df32.v%dbf16(<%d x float> %s, <%d x bfloat> %%%s, <%d x bfloat> %s)\n",
		result, form.lanes, form.lanes, inputArrangement.lanes,
		form.lanes, accumulator, inputArrangement.lanes, leftBFloat,
		inputArrangement.lanes, rightValue)
	return c.storeARM64VectorFloat(accumulatorReg, accumulatorArrangement, "%"+result)
}
