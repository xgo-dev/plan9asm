package plan9asm

import "fmt"

type armRawNEONMinMax struct {
	minimum     bool
	floating    bool
	unsigned    bool
	quad        bool
	elementBits int
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawNEONMinMax covers the complete classic A32 Advanced SIMD
// VMAX/VMIN family described by LLVM 22's ARMInstrNEON.td: signed and
// unsigned 8/16/32-bit integers plus 16/32-bit floating point, for both D and
// Q vectors. ARMv8 VMAXNM/VMINNM encodings are a separate instruction family.
func decodeARMRawNEONMinMax(word uint32) (armRawNEONMinMax, bool) {
	// N3V fixes 31:25=1111001 and bit 23=0.
	if word&0xfe800000 != 0xf2000000 {
		return armRawNEONMinMax{}, false
	}
	op := int(word>>8) & 15
	size := int(word>>20) & 3
	minimum := false
	floating := false
	unsigned := false
	elementBits := 0
	switch op {
	case 0b0110:
		if size == 3 {
			return armRawNEONMinMax{}, false
		}
		minimum = word>>4&1 != 0
		unsigned = word>>24&1 != 0
		elementBits = 8 << size
	case 0b1111:
		if word>>24&1 != 0 || word>>4&1 != 0 {
			return armRawNEONMinMax{}, false
		}
		floating = true
		minimum = size >= 2
		if size&1 == 0 {
			elementBits = 32
		} else {
			elementBits = 16
		}
	default:
		return armRawNEONMinMax{}, false
	}

	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	lhs := int(word>>16)&15 | int(word>>7&1)*16
	rhs := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || lhs&1 != 0 || rhs&1 != 0) {
		return armRawNEONMinMax{}, false
	}
	return armRawNEONMinMax{
		minimum:     minimum,
		floating:    floating,
		unsigned:    unsigned,
		quad:        quad,
		elementBits: elementBits,
		destination: destination,
		lhs:         lhs,
		rhs:         rhs,
	}, true
}

func (c *armCtx) lowerRawNEONMinMax(form armRawNEONMinMax) error {
	elementType := fmt.Sprintf("i%d", form.elementBits)
	if form.floating {
		elementType = "half"
		if form.elementBits == 32 {
			elementType = "float"
		}
	}
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, form.elementBits, form.quad, elementType)
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, form.elementBits, form.quad, elementType)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.floating {
		operation := "maximum"
		if form.minimum {
			operation = "minimum"
		}
		fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.%s.v%df%d(<%d x %s> %s, <%d x %s> %s)\n", result, lanes, elementType, operation, lanes, form.elementBits, lanes, elementType, lhs, lanes, elementType, rhs)
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
		fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x %s> %s, %s\n", condition, predicate, lanes, elementType, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x %s> %s, <%d x %s> %s\n", result, lanes, condition, lanes, elementType, lhs, lanes, elementType, rhs)
	}
	return c.storeARMRawNEONVector(form.destination, form.elementBits, form.quad, elementType, "%"+result)
}
