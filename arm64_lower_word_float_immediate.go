package plan9asm

import (
	"fmt"
	"math"
)

type arm64RawFloatImmediate struct {
	arrangement arm64VectorArrangement
	laneValue   uint64
	destination int
}

var arm64RawFloatImmediateArrangements = map[uint32]arm64VectorArrangement{
	0x0f00fc00: {elementBits: 16, lanes: 4},
	0x4f00fc00: {elementBits: 16, lanes: 8},
	0x0f00f400: {elementBits: 32, lanes: 2},
	0x4f00f400: {elementBits: 32, lanes: 4},
	0x6f00f400: {elementBits: 64, lanes: 2},
}

func decodeARM64RawFloatImmediate(word uint32) (arm64RawFloatImmediate, bool) {
	const variable = uint32(7<<16 | 31<<5 | 31)
	arrangement, ok := arm64RawFloatImmediateArrangements[word&^variable]
	if !ok {
		return arm64RawFloatImmediate{}, false
	}
	immediate := byte(((word >> 16) & 7 << 5) | ((word >> 5) & 31))
	value := arm64ExpandedFloatImmediate(immediate)
	laneValue := math.Float64bits(value)
	switch arrangement.elementBits {
	case 16:
		laneValue = uint64(arm64Float16Bits(value))
	case 32:
		laneValue = uint64(math.Float32bits(float32(value)))
	}
	return arm64RawFloatImmediate{
		arrangement: arrangement,
		laneValue:   laneValue,
		destination: int(word) & 31,
	}, true
}

func arm64ExpandedFloatImmediate(immediate byte) float64 {
	sign := 1.0
	if immediate&0x80 != 0 {
		sign = -1
	}
	exponent := (1-int(immediate>>6&1))*4 + int(immediate>>4&3) - 3
	significand := float64(16+int(immediate&15)) / 16
	return sign * math.Ldexp(significand, exponent)
}

func (c *arm64Ctx) lowerRawFloatImmediate(form arm64RawFloatImmediate) error {
	return c.lowerARM64VectorFloatImmediateBits(
		form.arrangement,
		form.laneValue,
		Reg(fmt.Sprintf("V%d", form.destination)),
	)
}
