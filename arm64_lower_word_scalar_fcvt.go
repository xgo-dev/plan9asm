package plan9asm

import "fmt"

type arm64FloatToIntegerRounding uint8

const (
	arm64FloatRoundNearestEven arm64FloatToIntegerRounding = iota
	arm64FloatRoundTiesAway
	arm64FloatRoundPlusInf
	arm64FloatRoundMinusInf
	arm64FloatRoundZero
)

type arm64RawScalarFCVTToInt struct {
	rounding        arm64FloatToIntegerRounding
	unsigned        bool
	sourceBits      int
	destinationBits int
	source          int
	destination     int
}

func decodeARM64RawScalarFCVTToInt(word uint32) (arm64RawScalarFCVTToInt, bool) {
	normalized := word & 0x7f3ffc00 // Ignore sf, type, Rn, and Rd.
	rounding := arm64FloatRoundZero
	switch normalized &^ (1 << 16) {
	case 0x1e200000:
		rounding = arm64FloatRoundNearestEven
	case 0x1e240000:
		rounding = arm64FloatRoundTiesAway
	case 0x1e280000:
		rounding = arm64FloatRoundPlusInf
	case 0x1e300000:
		rounding = arm64FloatRoundMinusInf
	case 0x1e380000:
		rounding = arm64FloatRoundZero
	default:
		return arm64RawScalarFCVTToInt{}, false
	}

	sourceBits := 0
	switch word >> 22 & 3 {
	case 0:
		sourceBits = 32
	case 1:
		sourceBits = 64
	case 3:
		sourceBits = 16
	default:
		return arm64RawScalarFCVTToInt{}, false
	}
	destinationBits := 32
	if word&(1<<31) != 0 {
		destinationBits = 64
	}
	return arm64RawScalarFCVTToInt{
		rounding:        rounding,
		unsigned:        word&(1<<16) != 0,
		sourceBits:      sourceBits,
		destinationBits: destinationBits,
		source:          int(word>>5) & 31,
		destination:     int(word) & 31,
	}, true
}

func arm64ScalarFloatType(bits int) (typeName string, intrinsicSuffix string, ok bool) {
	switch bits {
	case 16:
		return "half", "f16", true
	case 32:
		return "float", "f32", true
	case 64:
		return "double", "f64", true
	default:
		return "", "", false
	}
}

func (c *arm64Ctx) lowerARM64ScalarFloatToInteger(
	source Reg,
	sourceBits int,
	destination Reg,
	destinationBits int,
	unsigned bool,
	rounding arm64FloatToIntegerRounding,
) error {
	return c.lowerARM64ScalarConversion(arm64ScalarConversionForm{
		arm64ScalarConversionSpec: arm64ScalarConversionSpec{floatBits: sourceBits, integerBits: destinationBits, unsigned: unsigned},
		source:                    source, destination: destination, rounding: rounding,
	})
}

func (c *arm64Ctx) lowerRawScalarFCVTToInt(form arm64RawScalarFCVTToInt) error {
	source := Reg(fmt.Sprintf("F%d", form.source))
	destination := ZR
	if form.destination != 31 {
		destination = Reg(fmt.Sprintf("R%d", form.destination))
	}
	return c.lowerARM64ScalarFloatToInteger(
		source,
		form.sourceBits,
		destination,
		form.destinationBits,
		form.unsigned,
		form.rounding,
	)
}
