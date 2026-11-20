package plan9asm

import "fmt"

// arm64RawFloatMultiplyLong describes the complete Advanced SIMD FP16FML
// FMLAL/FMLAL2/FMLSL/FMLSL2 family. The inputs are half-precision values and
// the accumulator/result is single precision.
type arm64RawFloatMultiplyLong struct {
	subtract    bool
	highHalf    bool
	byElement   bool
	lanes       int
	lane        int
	second      int
	first       int
	destination int
}

func decodeARM64RawFloatMultiplyLong(word uint32) (arm64RawFloatMultiplyLong, bool) {
	form := arm64RawFloatMultiplyLong{
		lanes:       2,
		lane:        -1,
		second:      int(word>>16) & 31,
		first:       int(word>>5) & 31,
		destination: int(word) & 31,
	}
	if word&(1<<30) != 0 {
		form.lanes = 4
	}

	// Vector encodings vary Q and the three five-bit register fields.
	switch word & 0xbfe0fc00 {
	case 0x0e20ec00: // FMLAL.
		return form, true
	case 0x2e20cc00: // FMLAL2.
		form.highHalf = true
		return form, true
	case 0x0ea0ec00: // FMLSL.
		form.subtract = true
		return form, true
	case 0x2ea0cc00: // FMLSL2.
		form.subtract, form.highHalf = true, true
		return form, true
	}

	// By-element encodings limit Rm to V0..V15 and encode lane H:L:M in
	// bits 11, 21, and 20. Q selects a two- or four-lane result.
	form.byElement = true
	form.second &= 15
	form.lane = int(word>>11)&1<<2 | int(word>>21)&1<<1 | int(word>>20)&1
	switch word & 0xbfc0f400 {
	case 0x0f800000: // FMLAL by element.
		return form, true
	case 0x2f808000: // FMLAL2 by element.
		form.highHalf = true
		return form, true
	case 0x0f804000: // FMLSL by element.
		form.subtract = true
		return form, true
	case 0x2f80c000: // FMLSL2 by element.
		form.subtract, form.highHalf = true, true
		return form, true
	default:
		return arm64RawFloatMultiplyLong{}, false
	}
}

func (c *arm64Ctx) lowerRawFloatMultiplyLong(form arm64RawFloatMultiplyLong) error {
	halfArrangement := arm64VectorArrangement{elementBits: 16, lanes: 8}
	floatArrangement := arm64VectorArrangement{elementBits: 32, lanes: form.lanes}
	first, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.first)), halfArrangement)
	if err != nil {
		return err
	}

	selectHalf := func(value string) string {
		selected := c.newTmp()
		offset := 0
		if form.highHalf {
			offset = form.lanes
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x half> %s, <8 x half> poison, <%d x i32> <", selected, value, form.lanes)
		for lane := 0; lane < form.lanes; lane++ {
			if lane != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", offset+lane)
		}
		c.b.WriteString(">\n")
		return "%" + selected
	}
	first = selectHalf(first)

	var second string
	if form.byElement {
		all, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.second)), halfArrangement)
		if err != nil {
			return err
		}
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <8 x half> %s, i32 %d\n", element, all, form.lane)
		seed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x half> poison, half %%%s, i32 0\n", seed, form.lanes, element)
		splat := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x half> %%%s, <%d x half> poison, <%d x i32> zeroinitializer\n",
			splat, form.lanes, seed, form.lanes, form.lanes)
		second = "%" + splat
	} else {
		all, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.second)), halfArrangement)
		if err != nil {
			return err
		}
		second = selectHalf(all)
	}

	vectorHalfType := fmt.Sprintf("<%d x half>", form.lanes)
	vectorFloatType := fmt.Sprintf("<%d x float>", form.lanes)
	wideFirst := c.newTmp()
	wideSecond := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fpext %s %s to %s\n", wideFirst, vectorHalfType, first, vectorFloatType)
	fmt.Fprintf(c.b, "  %%%s = fpext %s %s to %s\n", wideSecond, vectorHalfType, second, vectorFloatType)
	firstOperand := "%" + wideFirst
	if form.subtract {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negated, vectorFloatType, firstOperand)
		firstOperand = "%" + negated
	}
	accumulator, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), floatArrangement)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.v%df32(%s %s, %s %%%s, %s %s)\n",
		result, vectorFloatType, form.lanes,
		vectorFloatType, firstOperand, vectorFloatType, wideSecond, vectorFloatType, accumulator)
	return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), floatArrangement, "%"+result)
}
