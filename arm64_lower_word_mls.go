package plan9asm

import "fmt"

func decodeARM64RawMLS(word uint32) (arm64RawMUL, bool) {
	form := arm64RawMUL{element: -1}
	switch {
	case word&0xbf20fc00 == 0x2e209400: // vector, three same
	case word&0xbf00f400 == 0x2f004000: // vector, by element
		form.byElement = true
	default:
		return arm64RawMUL{}, false
	}
	return decodeARM64MultiplyVectorOperands(word, form)
}

func (c *arm64Ctx) lowerRawMLS(form arm64RawMUL) error {
	return c.lowerRawMultiplyAccumulate(form, "sub")
}

func (c *arm64Ctx) lowerRawMultiplyAccumulate(form arm64RawMUL, operation string) error {
	first, err := c.loadRawARM64VectorOperand(form.first, form.arrangement, 0, false)
	if err != nil {
		return err
	}
	secondLane := 0
	if form.byElement {
		secondLane = form.element
	}
	second, err := c.loadRawARM64VectorOperand(form.second, form.arrangement, secondLane, form.byElement)
	if err != nil {
		return err
	}
	accumulator, err := c.loadRawARM64VectorOperand(form.destination, form.arrangement, 0, false)
	if err != nil {
		return err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", form.arrangement.lanes, form.arrangement.elementBits)
	product := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, vectorType, first, second)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, operation, vectorType, accumulator, product)
	return c.storeRawARM64VectorResult(form.destination, form.arrangement, "%"+result, false)
}
