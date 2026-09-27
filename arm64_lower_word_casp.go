package plan9asm

import "fmt"

type arm64RawCASP struct {
	elementBits int
	acquire     bool
	release     bool
	expected    int
	newValue    int
	base        int
}

func decodeARM64RawCASP(word uint32) (arm64RawCASP, bool) {
	const variable = uint32(1<<30 | 1<<22 | 1<<15 | 0x1e<<16 | 31<<5 | 0x1e)
	if word&^variable != 0x08207c00 {
		return arm64RawCASP{}, false
	}
	elementBits := 32
	if word&(1<<30) != 0 {
		elementBits = 64
	}
	return arm64RawCASP{
		elementBits: elementBits,
		acquire:     word&(1<<22) != 0,
		release:     word&(1<<15) != 0,
		expected:    int(word>>16) & 31,
		newValue:    int(word) & 31,
		base:        int(word>>5) & 31,
	}, true
}

func arm64RawCASPRegisterPair(first int) []Reg {
	second := Reg(fmt.Sprintf("R%d", first+1))
	if first == 30 {
		second = ZR
	}
	return []Reg{Reg(fmt.Sprintf("R%d", first)), second}
}

func (c *arm64Ctx) lowerRawCASP(form arm64RawCASP) error {
	base := Reg(fmt.Sprintf("R%d", form.base))
	if form.base == 31 {
		base = Reg("RSP")
	}
	ptr, err := c.atomicPairMemPtr(MemRef{Base: base}, false)
	if err != nil {
		return err
	}
	successOrder, failureOrder := "monotonic", "monotonic"
	if form.acquire && form.release {
		successOrder, failureOrder = "acq_rel", "acquire"
	} else if form.acquire {
		successOrder, failureOrder = "acquire", "acquire"
	} else if form.release {
		successOrder = "release"
	}
	return c.lowerAtomicPairCompareExchange(
		arm64RawCASPRegisterPair(form.expected),
		arm64RawCASPRegisterPair(form.newValue),
		form.elementBits, ptr, successOrder, failureOrder,
	)
}
