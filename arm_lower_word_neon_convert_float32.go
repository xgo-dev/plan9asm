package plan9asm

import "fmt"

type armRawNEONConvertFloat32 struct {
	toFloat     bool
	unsigned    bool
	quad        bool
	destination int
	source      int
}

// decodeARMRawNEONConvertFloat32 covers all eight classic A32 NEON VCVT
// integer/float32 forms: signed or unsigned, both directions, and D or Q
// vectors. Fixed-point, FP16, and ARMv8 directed-rounding encodings are
// separate architectural families.
func decodeARMRawNEONConvertFloat32(word uint32) (armRawNEONConvertFloat32, bool) {
	if word&0xffbf0010 != 0xf3bb0000 {
		return armRawNEONConvertFloat32{}, false
	}
	op := int(word>>7) & 31
	if op < 0b01100 || op > 0b01111 {
		return armRawNEONConvertFloat32{}, false
	}
	quad := word>>6&1 != 0
	destination := int(word>>12)&15 | int(word>>22&1)*16
	source := int(word)&15 | int(word>>5&1)*16
	if quad && (destination&1 != 0 || source&1 != 0) {
		return armRawNEONConvertFloat32{}, false
	}
	return armRawNEONConvertFloat32{
		toFloat:     op == 0b01100 || op == 0b01101,
		unsigned:    op == 0b01101 || op == 0b01111,
		quad:        quad,
		destination: destination,
		source:      source,
	}, true
}

func (c *armCtx) lowerRawNEONConvertFloat32(form armRawNEONConvertFloat32) error {
	sourceType := "i32"
	destinationType := "float"
	operation := "sitofp"
	if form.toFloat {
		if form.unsigned {
			operation = "uitofp"
		}
	} else {
		sourceType = "float"
		destinationType = "i32"
		operation = "fptosi"
		if form.unsigned {
			operation = "fptoui"
		}
	}
	source, lanes, err := c.loadARMRawNEONVector(form.source, 32, form.quad, sourceType)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x %s> %s to <%d x %s>\n", result, operation, lanes, sourceType, source, lanes, destinationType)
	return c.storeARMRawNEONVector(form.destination, 32, form.quad, destinationType, "%"+result)
}
