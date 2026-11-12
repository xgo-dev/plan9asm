package plan9asm

// decodeARMRawNEONStructureOneLane covers A32 VLD1/VST1 one-lane transfers
// for 8-, 16-, and 32-bit elements, including all lane, register, alignment,
// and post-index fields. It shares the typed memory lowerer with VLD4/VST4.
func decodeARMRawNEONStructureOneLane(word uint32) (armRawNEONStructureLane, bool) {
	if word&0xff900000 != 0xf4800000 {
		return armRawNEONStructureLane{}, false
	}
	form := armRawNEONStructureLane{
		load:   word>>21&1 != 0,
		first:  int(word>>12)&15 | int(word>>22&1)*16,
		stride: 1,
		base:   int(word>>16) & 15,
		offset: int(word) & 15,
	}
	switch word >> 8 & 15 {
	case 0:
		if word>>4&1 != 0 {
			return armRawNEONStructureLane{}, false
		}
		form.elementBits = 8
		form.lane = int(word >> 5 & 7)
	case 4:
		if word>>5&1 != 0 {
			return armRawNEONStructureLane{}, false
		}
		form.elementBits = 16
		form.lane = int(word >> 6 & 3)
		if word>>4&1 != 0 {
			form.alignment = 2
		}
	case 8:
		if word>>6&1 != 0 {
			return armRawNEONStructureLane{}, false
		}
		form.elementBits = 32
		form.lane = int(word >> 7 & 1)
		switch word >> 4 & 3 {
		case 0:
		case 3:
			form.alignment = 4
		default:
			return armRawNEONStructureLane{}, false
		}
	default:
		return armRawNEONStructureLane{}, false
	}
	return form, true
}
