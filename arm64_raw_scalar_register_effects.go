package plan9asm

// This scalar physical operand grammar is shared by native GP/R27/NZCV
// observers. Go's obj7 cases 3 and 27 use these exact encoding classes,
// including aliases. It supplies effects only, never a frame or input fact.
type arm64RawScalarRegister struct {
	width                      int
	first, second, destination int
	extended                   bool
	flags                      bool
}

func decodeARM64RawScalarRegister(word uint32) (arm64RawScalarRegister, bool) {
	width := 32
	if word>>31 != 0 {
		width = 64
	}
	form := arm64RawScalarRegister{
		width: width, first: int(word>>5) & 31,
		second: int(word>>16) & 31, destination: int(word) & 31,
	}
	switch {
	case word&0x1f000000 == 0x0a000000:
		// Logical shifted register: all four shifts, both complement states,
		// and AND/OR/EOR/ANDS. W shifts must not set imm6's high bit.
		if int(word>>10&63) >= width {
			return arm64RawScalarRegister{}, false
		}
		form.flags = word>>29&3 == 3
	case word&0x1f200000 == 0x0b000000:
		// ADD/SUB shifted register: ROR is reserved, unlike logical shifts.
		if word>>22&3 == 3 || int(word>>10&63) >= width {
			return arm64RawScalarRegister{}, false
		}
		form.flags = word&(1<<29) != 0
	case word&0x1fe00000 == 0x0b200000:
		// ADD/SUB extended register: all eight extensions, shift 0..4.
		// Rm=31 is zero even where Rn or a non-S Rd=31 denotes SP.
		if word>>10&7 > 4 {
			return arm64RawScalarRegister{}, false
		}
		form.extended = true
		form.flags = word&(1<<29) != 0
	default:
		return arm64RawScalarRegister{}, false
	}
	return form, true
}

func (form arm64RawScalarRegister) gpEffects() (reads, writes uint32, stack bool) {
	if form.second != 31 {
		reads |= 1 << uint(form.second)
	}
	if form.first != 31 {
		reads |= 1 << uint(form.first)
	} else if form.extended {
		stack = true
	}
	if form.destination != 31 {
		writes |= 1 << uint(form.destination)
	} else if form.extended && !form.flags {
		stack = true
	}
	return reads, writes, stack
}
