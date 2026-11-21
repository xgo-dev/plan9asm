package plan9asm

import "fmt"

type arm64RawScalarSIMDFloatToInt struct {
	rounding    arm64FloatToIntegerRounding
	unsigned    bool
	bits        int
	source      int
	destination int
}

// Advanced SIMD scalar conversions write integer bits to the F/V bank. Their
// width, rounding mode, signedness, and register fields are independent.
func decodeARM64RawScalarSIMDFloatToInt(word uint32) (arm64RawScalarSIMDFloatToInt, bool) {
	const registers = 31 | 31<<5
	const unsigned = 1 << 29
	const precision = 0x00780000

	var rounding arm64FloatToIntegerRounding
	switch word &^ (registers | unsigned | precision) {
	case 0x5e01a800:
		rounding = arm64FloatRoundNearestEven
	case 0x5e01c800:
		rounding = arm64FloatRoundTiesAway
	case 0x5e81a800:
		rounding = arm64FloatRoundPlusInf
	case 0x5e01b800:
		rounding = arm64FloatRoundMinusInf
	case 0x5e81b800:
		rounding = arm64FloatRoundZero
	default:
		return arm64RawScalarSIMDFloatToInt{}, false
	}

	var bits int
	switch word & precision {
	case 0x00780000:
		bits = 16
	case 0x00200000:
		bits = 32
	case 0x00600000:
		bits = 64
	default:
		return arm64RawScalarSIMDFloatToInt{}, false
	}

	return arm64RawScalarSIMDFloatToInt{
		rounding:    rounding,
		unsigned:    word&unsigned != 0,
		bits:        bits,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarSIMDFloatToInt(form arm64RawScalarSIMDFloatToInt) error {
	return c.lowerARM64ScalarConversion(arm64ScalarConversionForm{
		arm64ScalarConversionSpec: arm64ScalarConversionSpec{
			floatBits: form.bits, integerBits: form.bits, unsigned: form.unsigned, simdInteger: true,
		},
		source: Reg(fmt.Sprintf("F%d", form.source)), destination: Reg(fmt.Sprintf("F%d", form.destination)),
		rounding: form.rounding,
	})
}
