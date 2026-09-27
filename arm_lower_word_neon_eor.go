package plan9asm

import "fmt"

type armRawNEONEOR struct {
	operation   string
	quad        bool
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawNEONBitwise covers the complete classic A32 Advanced SIMD
// VAND/VBIC/VORR/VORN/VEOR register families for D and Q registers.
func decodeARMRawNEONBitwise(word uint32) (armRawNEONEOR, bool) {
	const variable = uint32(0x00400000 | 0x000f0000 | 0x0000f000 | 0x00000080 | 0x00000040 | 0x00000020 | 0x0000000f)
	operation := ""
	switch word &^ variable {
	case 0xf2000110:
		operation = "and"
	case 0xf2100110:
		operation = "bic"
	case 0xf2300110:
		operation = "orn"
	case 0xf3000110:
		operation = "xor"
	case 0xf2200110:
		operation = "or"
	default:
		return armRawNEONEOR{}, false
	}

	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	lhs := int(word>>16)&15 | int(word>>7&1)*16
	rhs := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || lhs&1 != 0 || rhs&1 != 0) {
		return armRawNEONEOR{}, false
	}
	return armRawNEONEOR{
		operation:   operation,
		quad:        quad,
		destination: destination,
		lhs:         lhs,
		rhs:         rhs,
	}, true
}

func decodeARMRawNEONEOR(word uint32) (armRawNEONEOR, bool) {
	form, ok := decodeARMRawNEONBitwise(word)
	return form, ok && form.operation == "xor"
}

func (c *armCtx) lowerRawNEONBitwise(form armRawNEONEOR) error {
	lhs, lanes, err := c.loadARMRawNEONVector(form.lhs, 64, form.quad, "i64")
	if err != nil {
		return err
	}
	rhs, _, err := c.loadARMRawNEONVector(form.rhs, 64, form.quad, "i64")
	if err != nil {
		return err
	}
	operation := form.operation
	if operation == "bic" || operation == "orn" {
		inverted := c.newTmp()
		allOnes := "<i64 -1>"
		if lanes == 2 {
			allOnes = "<i64 -1, i64 -1>"
		}
		fmt.Fprintf(c.b, "  %%%s = xor <%d x i64> %s, %s\n",
			inverted, lanes, rhs, allOnes)
		rhs = "%" + inverted
		operation = "and"
		if form.operation == "orn" {
			operation = "or"
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i64> %s, %s\n", result, operation, lanes, lhs, rhs)
	return c.storeARMRawNEONVector(form.destination, 64, form.quad, "i64", "%"+result)
}
