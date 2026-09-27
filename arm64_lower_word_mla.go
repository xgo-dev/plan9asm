package plan9asm

func decodeARM64RawMLA(word uint32) (arm64RawMUL, bool) {
	form := arm64RawMUL{element: -1}
	switch {
	case word&0xbf20fc00 == 0x0e209400: // vector, three same
	case word&0xbf00f400 == 0x2f000000: // vector, by element
		form.byElement = true
	default:
		return arm64RawMUL{}, false
	}
	return decodeARM64MultiplyVectorOperands(word, form)
}

func (c *arm64Ctx) lowerRawMLA(form arm64RawMUL) error {
	return c.lowerRawMultiplyAccumulate(form, "add")
}
