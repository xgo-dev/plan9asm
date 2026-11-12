package plan9asm

import "fmt"

type arm64RawFloatMinMaxAcross struct {
	operation   string
	arrangement arm64VectorArrangement
	source      int
	destination int
}

var arm64RawFloatMinMaxAcrossSpecs = map[uint32]struct {
	operation   string
	arrangement arm64VectorArrangement
}{
	0x0e30c800: {"maxnum", arm64VectorArrangement{16, 4}},
	0x4e30c800: {"maxnum", arm64VectorArrangement{16, 8}},
	0x6e30c800: {"maxnum", arm64VectorArrangement{32, 4}},
	0x0eb0c800: {"minnum", arm64VectorArrangement{16, 4}},
	0x4eb0c800: {"minnum", arm64VectorArrangement{16, 8}},
	0x6eb0c800: {"minnum", arm64VectorArrangement{32, 4}},
	0x0e30f800: {"maximum", arm64VectorArrangement{16, 4}},
	0x4e30f800: {"maximum", arm64VectorArrangement{16, 8}},
	0x6e30f800: {"maximum", arm64VectorArrangement{32, 4}},
	0x0eb0f800: {"minimum", arm64VectorArrangement{16, 4}},
	0x4eb0f800: {"minimum", arm64VectorArrangement{16, 8}},
	0x6eb0f800: {"minimum", arm64VectorArrangement{32, 4}},
}

func decodeARM64RawFloatMinMaxAcross(word uint32) (arm64RawFloatMinMaxAcross, bool) {
	const registers = uint32(31 | 31<<5)
	spec, ok := arm64RawFloatMinMaxAcrossSpecs[word&^registers]
	if !ok {
		return arm64RawFloatMinMaxAcross{}, false
	}
	return arm64RawFloatMinMaxAcross{
		operation:   spec.operation,
		arrangement: spec.arrangement,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFloatMinMaxAcross(form arm64RawFloatMinMaxAcross) error {
	return c.lowerARM64FloatMinMaxAcrossValues(
		form.operation,
		form.arrangement,
		Reg(fmt.Sprintf("V%d", form.source)),
		Reg(fmt.Sprintf("F%d", form.destination)),
	)
}
