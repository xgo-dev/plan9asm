package plan9asm

import "fmt"

type arm64RawSSHR struct {
	scalar      bool
	arrangement arm64VectorArrangement
	shift       int
	source      int
	destination int
}

func decodeARM64RawSSHR(word uint32) (arm64RawSSHR, bool) {
	form := arm64RawSSHR{}
	switch {
	case word&0xff80fc00 == 0x5f000400:
		form.scalar = true
	case word&0xbf80fc00 == 0x0f000400:
	default:
		return arm64RawSSHR{}, false
	}
	encodedImmediate := int(word>>16) & 0x7f
	bits := 0
	switch {
	case encodedImmediate >= 64:
		bits = 64
	case encodedImmediate >= 32:
		bits = 32
	case encodedImmediate >= 16:
		bits = 16
	case encodedImmediate >= 8:
		bits = 8
	default:
		return arm64RawSSHR{}, false
	}
	shift := 2*bits - encodedImmediate
	if shift < 1 || shift > bits || form.scalar && bits != 64 {
		return arm64RawSSHR{}, false
	}
	vectorBits := 64
	if form.scalar {
		form.arrangement = arm64VectorArrangement{elementBits: 64, lanes: 1}
	} else {
		if word&(1<<30) != 0 {
			vectorBits = 128
		}
		if bits == 64 && vectorBits != 128 {
			return arm64RawSSHR{}, false
		}
		form.arrangement = arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits}
	}
	form.shift = shift
	form.source = int(word>>5) & 31
	form.destination = int(word & 31)
	return form, true
}

func (c *arm64Ctx) lowerRawSSHR(form arm64RawSSHR) error {
	source, err := c.loadRawARM64VectorOperand(form.source, form.arrangement, 0, form.scalar)
	if err != nil {
		return err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", form.arrangement.lanes, form.arrangement.elementBits)
	result := c.newTmp()
	shift := form.shift
	if shift == form.arrangement.elementBits {
		// LLVM shifts by the element width are poison. AArch64 SSHR by the
		// element width instead replicates the sign bit, which is equivalent to
		// an arithmetic shift by width-1.
		shift--
	}
	fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", result, vectorType, source, arm64VectorIntegerSplat(form.arrangement, int64(shift)))
	return c.storeRawARM64VectorResult(form.destination, form.arrangement, "%"+result, form.scalar)
}
