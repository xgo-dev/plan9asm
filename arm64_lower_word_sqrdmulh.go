package plan9asm

// decodeARM64RawSQRDMULH covers every fixed-width Advanced SIMD SQRDMULH
// encoding. Go 1.27 names only the SVE form, ZSQRDMULH, so fixed-width users
// carry these instructions as WORD directives.
func decodeARM64RawSQRDMULH(word uint32) (arm64RawSQDMULH, bool) {
	form := arm64RawSQDMULH{element: -1}
	switch {
	case word&0xff20fc00 == 0x7e20b400: // scalar, three same
		form.scalar = true
	case word&0xbf20fc00 == 0x2e20b400: // vector, three same
	case word&0xff00f400 == 0x5f00d000: // scalar, by element
		form.scalar = true
		form.byElement = true
	case word&0xbf00f400 == 0x0f00d000: // vector, by element
		form.byElement = true
	default:
		return arm64RawSQDMULH{}, false
	}

	return decodeARM64MultiplyHighOperands(word, form)
}

func (c *arm64Ctx) lowerRawSQRDMULH(form arm64RawSQDMULH) error {
	return c.lowerRawSaturatingDoublingMultiplyHigh(form, true)
}
