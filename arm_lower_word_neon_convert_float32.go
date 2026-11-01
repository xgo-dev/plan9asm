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
	wordKind := "s32"
	if form.unsigned {
		wordKind = "u32"
	}
	sourceKind, destinationKind := wordKind, "f32"
	if !form.toFloat {
		sourceType = "float"
		destinationType = "i32"
		sourceKind, destinationKind = "f32", wordKind
	}
	source, lanes, err := c.loadARMRawNEONVector(form.source, 32, form.quad, sourceType)
	if err != nil {
		return err
	}
	result := c.newTmp()
	// Advanced SIMD VCVT uses standard rounding/denormal controls, not the
	// scalar VFP operation's ambient FPSCR mode. Its cumulative exceptions
	// still update native FPSCR, even for dead outputs. Keep the whole D/Q
	// operation and order it with the existing VMRS/VMSR memory barriers.
	// LLVM22's w constraint selects D0..31 / Q0..15 for these vector widths.
	operation := "vcvt." + destinationKind + "." + sourceKind + " $0, $1"
	fmt.Fprintf(c.b, "  %%%s = call <%d x %s> asm sideeffect %q, %q(<%d x %s> %s)\n",
		result, lanes, destinationType, operation, "=w,w,~{memory}", lanes, sourceType, source)
	return c.storeARMRawNEONVector(form.destination, 32, form.quad, destinationType, "%"+result)
}
