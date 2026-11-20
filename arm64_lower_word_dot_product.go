package plan9asm

import "fmt"

type arm64RawDotProduct struct {
	leftSigned  bool
	rightSigned bool
	indexed     bool
	lane        int
	lanes       int
	destination int
	left        int
	right       int
}

func decodeARM64RawDotProduct(word uint32) (arm64RawDotProduct, bool) {
	form := arm64RawDotProduct{lane: -1}
	switch word & 0xbfe0fc00 {
	case 0x0e809400: // SDOT (vector).
		form.leftSigned, form.rightSigned = true, true
	case 0x2e809400: // UDOT (vector).
	case 0x0e809c00: // USDOT (vector).
		form.rightSigned = true
	default:
		switch word & 0xbfc0f400 {
		case 0x0f80e000: // SDOT (by element).
			form.leftSigned, form.rightSigned = true, true
		case 0x2f80e000: // UDOT (by element).
		case 0x0f80f000: // USDOT (by element).
			form.rightSigned = true
		case 0x0f00f000: // SUDOT (by element).
			form.leftSigned = true
		default:
			return arm64RawDotProduct{}, false
		}
		form.indexed = true
		form.lane = int(word>>21)&1 | int(word>>10)&2
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

func (c *arm64Ctx) lowerRawDotProduct(form arm64RawDotProduct) error {
	byteLanes := form.lanes * 4
	inputArrangement := arm64VectorArrangement{elementBits: 8, lanes: byteLanes}
	accumulatorArrangement := arm64VectorArrangement{elementBits: 32, lanes: form.lanes}
	left, err := c.loadARM64VectorInteger(
		Reg(fmt.Sprintf("V%d.%s", form.left, arm64VectorArrangementName(inputArrangement))),
		inputArrangement,
	)
	if err != nil {
		return err
	}

	var right string
	if form.indexed {
		physical := arm64VectorArrangement{elementBits: 8, lanes: 16}
		loaded, err := c.loadARM64VectorInteger(
			Reg(fmt.Sprintf("V%d.%s", form.right, arm64VectorArrangementName(physical))),
			physical,
		)
		if err != nil {
			return err
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> poison, <%d x i32> <", selected, loaded, byteLanes)
		for i := 0; i < byteLanes; i++ {
			if i != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", form.lane*4+i%4)
		}
		c.b.WriteString(">\n")
		right = "%" + selected
	} else {
		right, err = c.loadARM64VectorInteger(
			Reg(fmt.Sprintf("V%d.%s", form.right, arm64VectorArrangementName(inputArrangement))),
			inputArrangement,
		)
		if err != nil {
			return err
		}
	}

	wideType := fmt.Sprintf("<%d x i32>", byteLanes)
	widen := func(value string, signed bool) string {
		result := c.newTmp()
		op := "zext"
		if signed {
			op = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s <%d x i8> %s to %s\n", result, op, byteLanes, value, wideType)
		return "%" + result
	}
	wideLeft := widen(left, form.leftSigned)
	wideRight := widen(right, form.rightSigned)
	products := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", products, wideType, wideLeft, wideRight)

	accumulatorReg := Reg(fmt.Sprintf("V%d.%s", form.destination, arm64VectorArrangementName(accumulatorArrangement)))
	result, err := c.loadARM64VectorInteger(accumulatorReg, accumulatorArrangement)
	if err != nil {
		return err
	}
	for lane := 0; lane < form.lanes; lane++ {
		accumulated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i32> %s, i32 %d\n", accumulated, form.lanes, result, lane)
		value := "%" + accumulated
		for element := 0; element < 4; element++ {
			product := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", product, wideType, products, lane*4+element)
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", sum, value, product)
			value = "%" + sum
		}
		updated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i32> %s, i32 %s, i32 %d\n", updated, form.lanes, result, value, lane)
		result = "%" + updated
	}
	return c.storeARM64VectorInteger(accumulatorReg, accumulatorArrangement, result)
}
