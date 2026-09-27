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
	floatType, floatSuffix, ok := arm64ScalarFloatType(sourceBits)
	if !ok {
		return fmt.Errorf("arm64 unsupported scalar float width %d", sourceBits)
	}
	sourceValue, err := c.loadARM64ScalarFloatReg(source, sourceBits)
	if err != nil {
		return err
	}

	roundingIntrinsic := ""
	switch rounding {
	case arm64FloatRoundNearestEven:
		roundingIntrinsic = "roundeven"
	case arm64FloatRoundTiesAway:
		roundingIntrinsic = "round"
	case arm64FloatRoundPlusInf:
		roundingIntrinsic = "ceil"
	case arm64FloatRoundMinusInf:
		roundingIntrinsic = "floor"
	case arm64FloatRoundZero:
	default:
		return fmt.Errorf("arm64 unsupported scalar float rounding mode %d", rounding)
	}
	if roundingIntrinsic != "" {
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n",
			rounded, floatType, roundingIntrinsic, floatSuffix, floatType, sourceValue)
		sourceValue = "%" + rounded
	}

	integerType := fmt.Sprintf("i%d", destinationBits)
	conversion := "fptosi.sat"
	if unsigned {
		conversion = "fptoui.sat"
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s.%s(%s %s)\n",
		converted, integerType, conversion, integerType, floatSuffix, floatType, sourceValue)
	value := "%" + converted
	if destinationBits == 32 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, value)
		value = "%" + wide
	} else if destinationBits != 64 {
		return fmt.Errorf("arm64 unsupported integer destination width %d", destinationBits)
	}
	return c.storeReg(destination, value)
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
