package plan9asm

import (
	"fmt"
	"strings"
)

type armRawNEONModifiedImmediate struct {
	kind        string
	cmode       int
	invert      bool
	quad        bool
	elementBits int
	destination int
	imm8        int
}

// decodeARMRawNEONModifiedImmediate covers A32 Advanced SIMD VMOV/VMVN
// modified-immediate register forms: i8, i16, i32, i64 byte-mask, and f32
// bit patterns. Odd cmodes 1..11 belong to VORR/VBIC, not to this family.
func decodeARMRawNEONModifiedImmediate(word uint32) (armRawNEONModifiedImmediate, bool) {
	const variable = uint32(0x01000000 | 0x00400000 | 0x00070000 |
		0x0000f000 | 0x00000f00 | 0x00000040 | 0x00000020 | 0x0000000f)
	if word&^variable != 0xf2800010 {
		return armRawNEONModifiedImmediate{}, false
	}
	cmode := int(word >> 8 & 15)
	invert := word>>5&1 != 0
	form := armRawNEONModifiedImmediate{
		kind:        "mov",
		cmode:       cmode,
		invert:      invert,
		quad:        word>>6&1 != 0,
		destination: int(word>>12)&15 | int(word>>22&1)*16,
		imm8:        int(word>>24&1)*128 | int(word>>16&7)*16 | int(word&15),
	}
	switch cmode {
	case 0, 2, 4, 6, 12, 13:
		form.elementBits = 32
	case 8, 10:
		form.elementBits = 16
	case 14:
		form.elementBits = 8
		if invert {
			form.elementBits = 64
		}
	case 15:
		if invert {
			return armRawNEONModifiedImmediate{}, false
		}
		form.elementBits = 32
		form.kind = "float"
	default:
		return armRawNEONModifiedImmediate{}, false
	}
	if invert && cmode < 14 {
		form.kind = "mvn"
	}
	if form.quad && form.destination&1 != 0 {
		return armRawNEONModifiedImmediate{}, false
	}
	return form, true
}

func expandARMRawNEONModifiedImmediate(form armRawNEONModifiedImmediate) uint64 {
	byteValue := uint64(form.imm8)
	var value uint64
	switch form.cmode {
	case 0, 2, 4, 6:
		value = byteValue << (form.cmode / 2 * 8)
	case 8, 10:
		value = byteValue << ((form.cmode - 8) / 2 * 8)
	case 12:
		value = byteValue<<8 | 0xff
	case 13:
		value = byteValue<<16 | 0xffff
	case 14:
		if form.invert {
			for index := 0; index < 8; index++ {
				if form.imm8>>index&1 != 0 {
					value |= uint64(0xff) << (index * 8)
				}
			}
		} else {
			value = byteValue
		}
	case 15:
		value = expandARMVFPImmediate(uint8(form.imm8), 32)
	}
	if form.kind == "mvn" {
		value = ^value
	}
	if form.elementBits < 64 {
		value &= uint64(1)<<form.elementBits - 1
	}
	return value
}

func (c *armCtx) lowerRawNEONModifiedImmediate(form armRawNEONModifiedImmediate) error {
	value := expandARMRawNEONModifiedImmediate(form)
	var signed int64
	switch form.elementBits {
	case 8:
		signed = int64(int8(value))
	case 16:
		signed = int64(int16(value))
	case 32:
		signed = int64(int32(value))
	case 64:
		signed = int64(value)
	}
	elementType := fmt.Sprintf("i%d", form.elementBits)
	lanes := 64 / form.elementBits
	if form.quad {
		lanes *= 2
	}
	constants := make([]string, lanes)
	for index := range constants {
		constants[index] = fmt.Sprintf("%s %d", elementType, signed)
	}
	return c.storeARMRawNEONVector(
		form.destination, form.elementBits, form.quad, elementType,
		"<"+strings.Join(constants, ", ")+">",
	)
}
