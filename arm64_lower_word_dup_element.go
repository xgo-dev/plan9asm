package plan9asm

type arm64RawDUPElement struct {
	arrangement arm64VectorArrangement
	element     int
	source      int
	destination int
}

func decodeARM64RawDUPElement(word uint32) (arm64RawDUPElement, bool) {
	if word&0xbfe0fc00 != 0x0e000400 {
		return arm64RawDUPElement{}, false
	}
	imm5 := int(word>>16) & 31
	bits := 0
	element := 0
	switch {
	case imm5&1 != 0:
		bits, element = 8, imm5>>1
	case imm5&2 != 0:
		bits, element = 16, imm5>>2
	case imm5&4 != 0:
		bits, element = 32, imm5>>3
	case imm5&8 != 0:
		bits, element = 64, imm5>>4
	default:
		return arm64RawDUPElement{}, false
	}
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	if bits == 64 && vectorBits == 64 {
		return arm64RawDUPElement{}, false
	}
	return arm64RawDUPElement{
		arrangement: arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits},
		element:     element,
		source:      int(word>>5) & 31,
		destination: int(word & 31),
	}, true
}

func (c *arm64Ctx) lowerRawDUPElement(form arm64RawDUPElement) error {
	value, err := c.loadRawARM64VectorOperand(form.source, form.arrangement, form.element, true)
	if err != nil {
		return err
	}
	return c.storeRawARM64VectorResult(form.destination, form.arrangement, value, false)
}
