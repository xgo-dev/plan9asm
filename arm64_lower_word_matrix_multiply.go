package plan9asm

import "fmt"

type arm64RawMatrixMultiply struct {
	leftSigned  bool
	rightSigned bool
	destination int
	left        int
	right       int
}

func decodeARM64RawMatrixMultiply(word uint32) (arm64RawMatrixMultiply, bool) {
	form := arm64RawMatrixMultiply{}
	switch word & 0xffe0fc00 {
	case 0x4e80a400: // SMMLA.
		form.leftSigned, form.rightSigned = true, true
	case 0x6e80a400: // UMMLA.
	case 0x4e80ac00: // USMMLA.
		form.rightSigned = true
	default:
		return arm64RawMatrixMultiply{}, false
	}
	form.destination = int(word) & 31
	form.left = int(word>>5) & 31
	form.right = int(word>>16) & 31
	return form, true
}

func (c *arm64Ctx) lowerRawMatrixMultiply(form arm64RawMatrixMultiply) error {
	inputArrangement := arm64VectorArrangement{elementBits: 8, lanes: 16}
	accumulatorArrangement := arm64VectorArrangement{elementBits: 32, lanes: 4}
	leftReg := Reg(fmt.Sprintf("V%d.B16", form.left))
	rightReg := Reg(fmt.Sprintf("V%d.B16", form.right))
	accumulatorReg := Reg(fmt.Sprintf("V%d.S4", form.destination))
	left, err := c.loadARM64VectorInteger(leftReg, inputArrangement)
	if err != nil {
		return err
	}
	right, err := c.loadARM64VectorInteger(rightReg, inputArrangement)
	if err != nil {
		return err
	}
	result, err := c.loadARM64VectorInteger(accumulatorReg, accumulatorArrangement)
	if err != nil {
		return err
	}

	widen := func(value string, signed bool) string {
		op := "zext"
		if signed {
			op = "sext"
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s <16 x i8> %s to <16 x i32>\n", wide, op, value)
		return "%" + wide
	}
	wideLeft := widen(left, form.leftSigned)

	for column := 0; column < 2; column++ {
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> poison, <16 x i32> <", selected, right)
		for lane := 0; lane < 16; lane++ {
			if lane != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", 2*(lane%8)+column)
		}
		c.b.WriteString(">\n")
		wideRight := widen("%"+selected, form.rightSigned)
		products := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul <16 x i32> %s, %s\n", products, wideLeft, wideRight)

		for row := 0; row < 2; row++ {
			destinationLane := row*2 + column
			accumulated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %s, i32 %d\n", accumulated, result, destinationLane)
			value := "%" + accumulated
			for k := 0; k < 8; k++ {
				product := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i32> %%%s, i32 %d\n", product, products, row*8+k)
				sum := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", sum, value, product)
				value = "%" + sum
			}
			updated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %s, i32 %s, i32 %d\n", updated, result, value, destinationLane)
			result = "%" + updated
		}
	}
	return c.storeARM64VectorInteger(accumulatorReg, accumulatorArrangement, result)
}
