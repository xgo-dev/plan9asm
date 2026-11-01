package plan9asm

import "fmt"

func decodeARM64RawConditionalCompare(word uint32) (arm64ConditionalCompareForm, bool) {
	const variable = uint32(31<<5 | 31<<16 | 3<<22 | 15<<12 | 1<<4 | 15)
	if word & ^variable != 0x1e200400 {
		return arm64ConditionalCompareForm{}, false
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
		return arm64ConditionalCompareForm{}, false
	}
	conditions := [...]string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}
	return arm64ConditionalCompareForm{
		arm64ScalarCompareForm: arm64ScalarCompareForm{
			bits: bits, signaling: word&(1<<4) != 0,
			left:  Reg(fmt.Sprintf("F%d", word>>5&31)),
			right: Reg(fmt.Sprintf("F%d", word>>16&31)),
		},
		condition: conditions[word>>12&15],
		nzcv:      uint8(word & 15),
	}, true
}
