package plan9asm

import "fmt"

type arm64RawScalarFloatCompare struct {
	bits      int
	signaling bool
	zero      bool
	first     int
	second    int
}

func decodeARM64RawScalarFloatCompare(word uint32) (arm64RawScalarFloatCompare, bool) {
	const (
		firstRegister  = uint32(31 << 5)
		secondRegister = uint32(31 << 16)
		floatType      = uint32(3 << 22)
		signalingBit   = uint32(1 << 4)
		zeroBit        = uint32(1 << 3)
		variableFields = firstRegister | secondRegister | floatType | signalingBit | zeroBit
		compareBase    = uint32(0x1e202000)
	)
	if word&^variableFields != compareBase {
		return arm64RawScalarFloatCompare{}, false
	}

	bits := 0
	switch word >> 22 & 3 {
	case 0:
		bits = 32
	case 1:
		bits = 64
	case 3:
		bits = 16
	default:
		return arm64RawScalarFloatCompare{}, false
	}
	second := int(word>>16) & 31
	zero := word&zeroBit != 0
	if zero && second != 0 {
		return arm64RawScalarFloatCompare{}, false
	}
	return arm64RawScalarFloatCompare{
		bits:      bits,
		signaling: word&signalingBit != 0,
		zero:      zero,
		first:     int(word>>5) & 31,
		second:    second,
	}, true
}

func (c *arm64Ctx) lowerRawScalarFloatCompare(form arm64RawScalarFloatCompare) error {
	floatType, _, ok := arm64ScalarFloatType(form.bits)
	if !ok {
		return fmt.Errorf("arm64 unsupported scalar float width %d", form.bits)
	}
	left, err := c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.first)), form.bits)
	if err != nil {
		return err
	}
	right := formatLLVMFloat64Literal(0)
	if !form.zero {
		right, err = c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.second)), form.bits)
		if err != nil {
			return err
		}
	}
	c.setARM64FloatCompareFlags(floatType, left, right)
	return nil
}
