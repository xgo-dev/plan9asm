package plan9asm

import "fmt"

type arm64RawFloatGPMove struct {
	bits     int
	toFloat  bool
	upper    bool
	floatReg int
	gpReg    int
}

var arm64RawFloatGPMoveSpecs = map[uint32]struct {
	bits    int
	toFloat bool
	upper   bool
}{
	0x1ee70000: {bits: 16, toFloat: true},
	0x1ee60000: {bits: 16},
	0x1e270000: {bits: 32, toFloat: true},
	0x1e260000: {bits: 32},
	0x9e670000: {bits: 64, toFloat: true},
	0x9e660000: {bits: 64},
	0x9eaf0000: {bits: 64, toFloat: true, upper: true},
	0x9eae0000: {bits: 64, upper: true},
}

func decodeARM64RawFloatGPMove(word uint32) (arm64RawFloatGPMove, bool) {
	const registers = uint32(31<<5 | 31)
	spec, ok := arm64RawFloatGPMoveSpecs[word&^registers]
	if !ok {
		return arm64RawFloatGPMove{}, false
	}

	source := int(word>>5) & 31
	destination := int(word) & 31
	floatReg, gpReg := destination, source
	if !spec.toFloat {
		floatReg, gpReg = source, destination
	}
	return arm64RawFloatGPMove{
		bits:     spec.bits,
		toFloat:  spec.toFloat,
		upper:    spec.upper,
		floatReg: floatReg,
		gpReg:    gpReg,
	}, true
}

func (c *arm64Ctx) lowerRawFloatGPMove(form arm64RawFloatGPMove) error {
	floatReg := Reg(fmt.Sprintf("F%d", form.floatReg))
	gpReg := ZR
	if form.gpReg != 31 {
		gpReg = Reg(fmt.Sprintf("R%d", form.gpReg))
	}

	if form.upper {
		return c.lowerRawFloatGPUpperMove(floatReg, gpReg, form.toFloat)
	}
	if form.toFloat {
		value, err := c.loadReg(gpReg)
		if err != nil {
			return err
		}
		return c.storeReg(floatReg, c.normalizeScalarFloatBits(value, form.bits))
	}
	value, err := c.loadReg(floatReg)
	if err != nil {
		return err
	}
	return c.storeReg(gpReg, c.normalizeScalarFloatBits(value, form.bits))
}

func (c *arm64Ctx) lowerRawFloatGPUpperMove(floatReg, gpReg Reg, toFloat bool) error {
	vector, err := c.loadVReg(floatReg)
	if err != nil {
		return err
	}
	lanes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", lanes, vector)
	if !toFloat {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i64 1\n", value, lanes)
		return c.storeReg(gpReg, "%"+value)
	}

	value, err := c.loadReg(gpReg)
	if err != nil {
		return err
	}
	updated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %s, i64 1\n", updated, lanes, value)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, updated)
	return c.storeVReg(floatReg, "%"+bytes)
}
