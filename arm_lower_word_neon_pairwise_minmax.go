package plan9asm

import "fmt"

type armRawNEONPairwiseMinMax struct {
	minimum     bool
	floating    bool
	unsigned    bool
	elementBits int
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawNEONPairwiseMinMax covers every classic A32 VPMAX/VPMIN form
// in LLVM 22's ARMInstrNEON.td: signed and unsigned 8/16/32-bit integers plus
// 16/32-bit floating point. Pairwise forms operate only on D registers.
func decodeARMRawNEONPairwiseMinMax(word uint32) (armRawNEONPairwiseMinMax, bool) {
	// N3VDInt fixes 31:25=1111001, bit 23=0, and bit 6=0.
	if word&0xfe800040 != 0xf2000000 {
		return armRawNEONPairwiseMinMax{}, false
	}
	op := int(word>>8) & 15
	size := int(word>>20) & 3
	minimum := false
	floating := false
	unsigned := false
	elementBits := 0
	switch op {
	case 0b1010:
		if size == 3 {
			return armRawNEONPairwiseMinMax{}, false
		}
		minimum = word>>4&1 != 0
		unsigned = word>>24&1 != 0
		elementBits = 8 << size
	case 0b1111:
		if word>>24&1 == 0 || word>>4&1 != 0 {
			return armRawNEONPairwiseMinMax{}, false
		}
		floating = true
		minimum = size >= 2
		if size&1 == 0 {
			elementBits = 32
		} else {
			elementBits = 16
		}
	default:
		return armRawNEONPairwiseMinMax{}, false
	}
	return armRawNEONPairwiseMinMax{
		minimum:     minimum,
		floating:    floating,
		unsigned:    unsigned,
		elementBits: elementBits,
		destination: int(word>>12)&15 | int(word>>22&1)*16,
		lhs:         int(word>>16)&15 | int(word>>7&1)*16,
		rhs:         int(word)&15 | int(word>>5&1)*16,
	}, true
}

func (c *armCtx) lowerRawNEONPairwiseMinMax(form armRawNEONPairwiseMinMax) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	if form.floating {
		elementType = "half"
		if form.elementBits == 32 {
			elementType = "float"
		}
	}
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, form.elementBits, false, elementType)
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, form.elementBits, false, elementType)
	if err != nil {
		return err
	}
	result := "poison"
	for destinationLane := 0; destinationLane < lanes; destinationLane++ {
		source := lhs
		sourceLane := destinationLane * 2
		if destinationLane >= lanes/2 {
			source = rhs
			sourceLane = (destinationLane - lanes/2) * 2
		}
		first := c.newTmp()
		second := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", first, lanes, elementType, source, sourceLane)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", second, lanes, elementType, source, sourceLane+1)
		selected := c.newTmp()
		if form.floating {
			operation := "maximum"
			if form.minimum {
				operation = "minimum"
			}
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.f%d(%s %%%s, %s %%%s)\n", selected, elementType, operation, form.elementBits, elementType, first, elementType, second)
		} else {
			predicate := "sgt"
			if form.unsigned {
				predicate = "ugt"
			}
			if form.minimum {
				predicate = "slt"
				if form.unsigned {
					predicate = "ult"
				}
			}
			condition := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, %%%s\n", condition, predicate, elementType, first, second)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %%%s\n", selected, condition, elementType, first, elementType, second)
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> %s, %s %%%s, i32 %d\n", inserted, lanes, elementType, result, elementType, selected, destinationLane)
		result = "%" + inserted
	}
	return c.storeARMRawNEONVector(form.destination, form.elementBits, false, elementType, result)
}
