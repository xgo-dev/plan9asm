package plan9asm

import "fmt"

type arm64RawScalarFloatBinary struct {
	kind        string
	bits        int
	first       int
	second      int
	destination int
}

var arm64RawScalarFloatBinarySpecs = map[uint32]struct {
	kind string
	bits int
}{
	0x1ee02800: {"add", 16},
	0x1e202800: {"add", 32},
	0x1e602800: {"add", 64},
	0x1ee03800: {"sub", 16},
	0x1e203800: {"sub", 32},
	0x1e603800: {"sub", 64},
	0x1ee00800: {"mul", 16},
	0x1e200800: {"mul", 32},
	0x1e600800: {"mul", 64},
	0x1ee08800: {"nmul", 16},
	0x1e208800: {"nmul", 32},
	0x1e608800: {"nmul", 64},
	0x1ee01800: {"div", 16},
	0x1e201800: {"div", 32},
	0x1e601800: {"div", 64},
	0x1ee04800: {"maximum", 16},
	0x1e204800: {"maximum", 32},
	0x1e604800: {"maximum", 64},
	0x1ee05800: {"minimum", 16},
	0x1e205800: {"minimum", 32},
	0x1e605800: {"minimum", 64},
	0x1ee06800: {"maxnum", 16},
	0x1e206800: {"maxnum", 32},
	0x1e606800: {"maxnum", 64},
	0x1ee07800: {"minnum", 16},
	0x1e207800: {"minnum", 32},
	0x1e607800: {"minnum", 64},
	0x7ec01400: {"fabd", 16},
	0x7ea0d400: {"fabd", 32},
	0x7ee0d400: {"fabd", 64},
	0x5e401c00: {"fmulx", 16},
	0x5e20dc00: {"fmulx", 32},
	0x5e60dc00: {"fmulx", 64},
}

func decodeARM64RawScalarFloatBinary(word uint32) (arm64RawScalarFloatBinary, bool) {
	const registers = uint32(31 | 31<<5 | 31<<16)
	spec, ok := arm64RawScalarFloatBinarySpecs[word&^registers]
	if !ok {
		return arm64RawScalarFloatBinary{}, false
	}
	return arm64RawScalarFloatBinary{
		kind:        spec.kind,
		bits:        spec.bits,
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarFloatBinary(form arm64RawScalarFloatBinary) error {
	lhs, err := c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.first)), form.bits)
	if err != nil {
		return err
	}
	rhs, err := c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.second)), form.bits)
	if err != nil {
		return err
	}
	return c.lowerARM64ScalarFloatBinaryValues(
		form.kind,
		form.bits,
		lhs,
		rhs,
		Reg(fmt.Sprintf("F%d", form.destination)),
	)
}
