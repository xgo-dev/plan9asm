package plan9asm

import "fmt"

type arm64RawSVEFloatMinMaxReduction struct {
	spec        arm64SVEFloatMinMaxSpec
	form        arm64SVEFloatMinMaxForm
	destination Reg
}

// SVE's four predicated floating min/max reductions share one encoding
// grammar. The opcode nibble chooses max/min and NaN behavior; size chooses
// H/S/D; the remaining variable fields are Zd, Zn, and Pg.
func decodeARM64RawSVEFloatMinMaxReduction(word uint32) (arm64RawSVEFloatMinMaxReduction, bool) {
	if word&0xff30e000 != 0x65002000 {
		return arm64RawSVEFloatMinMaxReduction{}, false
	}

	size := int(word>>22) & 3
	opcode := int(word>>16) & 15
	if size == 0 || opcode < 4 || opcode > 7 {
		return arm64RawSVEFloatMinMaxReduction{}, false
	}

	operations := [...]string{"ZFMAXNMV", "ZFMINNMV", "ZFMAXV", "ZFMINV"}
	suffixes := [...]string{"", "H", "S", "D"}
	op := Op(operations[opcode-4] + suffixes[size])
	spec, ok := arm64SVEFloatMinMaxSpecs[op]
	if !ok {
		return arm64RawSVEFloatMinMaxReduction{}, false
	}

	destination := int(word) & 31
	return arm64RawSVEFloatMinMaxReduction{
		spec: spec,
		form: arm64SVEFloatMinMaxForm{
			elementBits: 8 << size,
			first:       int(word>>5) & 31,
			predicate:   int(word>>10) & 7,
			destination: destination,
		},
		destination: Reg(fmt.Sprintf("V%d", destination)),
	}, true
}
