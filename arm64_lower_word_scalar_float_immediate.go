package plan9asm

import "fmt"

type arm64RawScalarFloatImmediate struct {
	bits        int
	value       float64
	destination int
}

func decodeARM64RawScalarFloatImmediate(word uint32) (arm64RawScalarFloatImmediate, bool) {
	const (
		floatType      = uint32(3 << 22)
		immediateField = uint32(255 << 13)
		destination    = uint32(31)
		variableFields = floatType | immediateField | destination
		immediateBase  = uint32(0x1e201000)
	)
	if word&^variableFields != immediateBase {
		return arm64RawScalarFloatImmediate{}, false
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
		return arm64RawScalarFloatImmediate{}, false
	}
	immediate := byte(word >> 13)
	return arm64RawScalarFloatImmediate{
		bits:        bits,
		value:       arm64ExpandedFloatImmediate(immediate),
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawScalarFloatImmediate(form arm64RawScalarFloatImmediate) error {
	destination := Reg(fmt.Sprintf("F%d", form.destination))
	return c.storeARM64ScalarFloatReg(
		destination,
		form.bits,
		formatLLVMFloat64Literal(form.value),
	)
}
