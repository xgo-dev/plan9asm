package plan9asm

import "fmt"

type arm64RawUMULL struct {
	byElement   bool
	highHalf    bool
	source      arm64VectorArrangement
	destination arm64VectorArrangement
	destReg     int
	first       int
	second      int
	element     int
}

func decodeARM64RawUMULL(word uint32) (arm64RawUMULL, bool) {
	form := arm64RawUMULL{element: -1, highHalf: word&(1<<30) != 0}
	switch {
	case word&0xbf20fc00 == 0x2e20c000: // vector, three registers
	case word&0xbf00f400 == 0x2f00a000: // vector, by element
		form.byElement = true
	default:
		return arm64RawUMULL{}, false
	}
	size := int(word>>22) & 3
	if size > 2 || form.byElement && size == 0 {
		return arm64RawUMULL{}, false
	}
	sourceBits := 8 << size
	destLanes := 128 / (sourceBits * 2)
	sourceLanes := destLanes
	if form.highHalf {
		sourceLanes *= 2
	}
	form.source = arm64VectorArrangement{elementBits: sourceBits, lanes: sourceLanes}
	form.destination = arm64VectorArrangement{elementBits: sourceBits * 2, lanes: destLanes}
	form.destReg = int(word & 31)
	form.first = int(word>>5) & 31
	form.second = int(word>>16) & 31
	if form.byElement {
		form.second &= 15
		l := int(word>>21) & 1
		m := int(word>>20) & 1
		h := int(word>>11) & 1
		if sourceBits == 16 {
			form.element = h<<2 | l<<1 | m
		} else {
			form.second |= m << 4
			form.element = h<<1 | l
		}
	}
	return form, true
}

func (c *arm64Ctx) lowerRawUMULL(form arm64RawUMULL) error {
	first, err := c.loadRawARM64VectorOperand(form.first, form.source, 0, false)
	if err != nil {
		return err
	}
	if form.highHalf {
		first = c.selectARM64VectorHighHalf(form.source, form.destination.lanes, first)
	}
	selected := arm64VectorArrangement{elementBits: form.source.elementBits, lanes: form.destination.lanes}
	var second string
	if form.byElement {
		second, err = c.loadRawARM64VectorOperand(form.second, selected, form.element, true)
	} else {
		second, err = c.loadRawARM64VectorOperand(form.second, form.source, 0, false)
		if err == nil && form.highHalf {
			second = c.selectARM64VectorHighHalf(form.source, form.destination.lanes, second)
		}
	}
	if err != nil {
		return err
	}
	narrowType := fmt.Sprintf("<%d x i%d>", selected.lanes, selected.elementBits)
	wideType := fmt.Sprintf("<%d x i%d>", form.destination.lanes, form.destination.elementBits)
	wideFirst := c.newTmp()
	wideSecond := c.newTmp()
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", wideFirst, narrowType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", wideSecond, narrowType, second, wideType)
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", product, wideType, wideFirst, wideSecond)
	return c.storeRawARM64VectorResult(form.destReg, form.destination, "%"+product, false)
}
