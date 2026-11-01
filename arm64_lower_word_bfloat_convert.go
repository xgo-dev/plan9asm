package plan9asm

import "fmt"

type arm64RawBFloatConvert struct {
	vector      bool
	high        bool
	source      int
	destination int
}

var arm64RawBFloatConvertSpecs = map[uint32]struct {
	vector bool
	high   bool
}{
	0x1e634000: {},
	0x0ea16800: {vector: true},
	0x4ea16800: {vector: true, high: true},
}

func decodeARM64RawBFloatConvert(word uint32) (arm64RawBFloatConvert, bool) {
	const registers = uint32(31<<5 | 31)
	spec, ok := arm64RawBFloatConvertSpecs[word&^registers]
	if !ok {
		return arm64RawBFloatConvert{}, false
	}
	return arm64RawBFloatConvert{
		vector:      spec.vector,
		high:        spec.high,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawBFloatConvert(form arm64RawBFloatConvert) error {
	if !form.vector {
		source, err := c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.source)), 32)
		if err != nil {
			return err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptrunc float %s to bfloat\n", converted, source)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast bfloat %%%s to i16\n", bits, converted)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i64\n", wide, bits)
		return c.storeReg(Reg(fmt.Sprintf("F%d", form.destination)), "%"+wide)
	}

	source, err := c.loadVReg(Reg(fmt.Sprintf("V%d", form.source)))
	if err != nil {
		return err
	}
	floats := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", floats, source)
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fptrunc <4 x float> %%%s to <4 x bfloat>\n", converted, floats)
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x bfloat> %%%s to i64\n", bits, converted)

	lanes := "zeroinitializer"
	destination := Reg(fmt.Sprintf("V%d", form.destination))
	if form.high {
		original, err := c.loadVReg(destination)
		if err != nil {
			return err
		}
		existing := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", existing, original)
		lanes = "%" + existing
	}
	lane := 0
	if form.high {
		lane = 1
	}
	updated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %s, i64 %%%s, i64 %d\n", updated, lanes, bits, lane)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, updated)
	return c.storeVReg(destination, "%"+bytes)
}
