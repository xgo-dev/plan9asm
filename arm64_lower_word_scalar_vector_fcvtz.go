package plan9asm

import "fmt"

type arm64RawScalarVectorFCVTZ struct {
	unsigned    bool
	bits        int
	source      int
	destination int
}

// The scalar Advanced SIMD FCVTZS/FCVTZU forms convert floating-point bits
// to integer bits in an F/V register. They are distinct from both the vector
// forms and Go's named scalar conversions to a general-purpose register.
func decodeARM64RawScalarVectorFCVTZ(word uint32) (arm64RawScalarVectorFCVTZ, bool) {
	const registers = uint32(31 | 31<<5)
	forms := map[uint32]struct {
		unsigned bool
		bits     int
	}{
		0x5ef9b800: {false, 16},
		0x5ea1b800: {false, 32},
		0x5ee1b800: {false, 64},
		0x7ef9b800: {true, 16},
		0x7ea1b800: {true, 32},
		0x7ee1b800: {true, 64},
	}
	form, ok := forms[word&^registers]
	if !ok {
		return arm64RawScalarVectorFCVTZ{}, false
	}
	return arm64RawScalarVectorFCVTZ{
		unsigned:    form.unsigned,
		bits:        form.bits,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarVectorFCVTZ(form arm64RawScalarVectorFCVTZ) error {
	sourceReg := Reg(fmt.Sprintf("F%d", form.source))
	destinationReg := Reg(fmt.Sprintf("F%d", form.destination))
	source, err := c.loadARM64ScalarFloatReg(sourceReg, form.bits)
	if err != nil {
		return err
	}
	floatType, floatSuffix, ok := arm64ScalarFloatType(form.bits)
	if !ok {
		return fmt.Errorf("arm64 unsupported scalar conversion width %d", form.bits)
	}
	conversion := "fptosi.sat"
	if form.unsigned {
		conversion = "fptoui.sat"
	}
	integerType := fmt.Sprintf("i%d", form.bits)
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s.%s(%s %s)\n",
		converted, integerType, conversion, integerType, floatSuffix, floatType, source)
	value := "%" + converted
	if form.bits < 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, integerType, value)
		value = "%" + wide
	}
	return c.storeReg(destinationReg, value)
}
