package plan9asm

import "fmt"

type arm64RawMUL struct {
	byElement   bool
	arrangement arm64VectorArrangement
	destination int
	first       int
	second      int
	element     int
}

func decodeARM64RawMUL(word uint32) (arm64RawMUL, bool) {
	form := arm64RawMUL{element: -1}
	switch {
	case word&0xbf20fc00 == 0x0e209c00: // vector, three same
	case word&0xbf00f400 == 0x0f008000: // vector, by element
		form.byElement = true
	default:
		return arm64RawMUL{}, false
	}
	return decodeARM64MultiplyVectorOperands(word, form)
}

func decodeARM64MultiplyVectorOperands(word uint32, form arm64RawMUL) (arm64RawMUL, bool) {
	size := int(word>>22) & 3
	if form.byElement {
		if size != 1 && size != 2 {
			return arm64RawMUL{}, false
		}
	} else if size > 2 {
		return arm64RawMUL{}, false
	}
	bits := 8 << size
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	form.arrangement = arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits}
	form.destination = int(word & 31)
	form.first = int(word>>5) & 31
	form.second = int(word>>16) & 31
	if form.byElement {
		element := decodeARM64MultiplyIndexedElement(word, bits)
		form.second, form.element = element.register, element.lane
	}
	return form, true
}

type arm64MultiplyIndexedElement struct {
	register int
	lane     int
}

// All callers validate H/S size first. Arm DDI 0602 uses H:L:M for halfword
// lane indices, H:L for word indices, and M:Rm for the word source register.
func decodeARM64MultiplyIndexedElement(word uint32, bits int) arm64MultiplyIndexedElement {
	h := int(word>>11) & 1
	l := int(word>>21) & 1
	m := int(word>>20) & 1
	reg := int(word>>16) & 15
	if bits == 16 {
		return arm64MultiplyIndexedElement{register: reg, lane: h<<2 | l<<1 | m}
	}
	return arm64MultiplyIndexedElement{register: m<<4 | reg, lane: h<<1 | l}
}

func (c *arm64Ctx) lowerRawMUL(form arm64RawMUL) error {
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
	vectorType := fmt.Sprintf("<%d x i%d>", form.arrangement.lanes, form.arrangement.elementBits)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, vectorType, first, second)
	return c.storeRawARM64VectorResult(form.destination, form.arrangement, "%"+product, false)
}
