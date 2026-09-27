package plan9asm

import "fmt"

type arm64RawHalvingAddSub struct {
	spec        arm64HalvingAddSubSpec
	arrangement arm64VectorArrangement
	destination int
	first       int
	second      int
}

var arm64RawHalvingAddSubSpecs = map[uint32]arm64HalvingAddSubSpec{
	0x0e200400: {signed: true},
	0x2e200400: {},
	0x0e201400: {signed: true, rounding: true},
	0x2e201400: {rounding: true},
	0x0e202400: {signed: true, subtract: true},
	0x2e202400: {subtract: true},
}

func decodeARM64RawHalvingAddSub(word uint32) (arm64RawHalvingAddSub, bool) {
	spec, ok := arm64RawHalvingAddSubSpecs[word&0xbf20fc00]
	if !ok {
		return arm64RawHalvingAddSub{}, false
	}
	size := int(word>>22) & 3
	if size > 2 {
		return arm64RawHalvingAddSub{}, false
	}
	bits := 8 << size
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	return arm64RawHalvingAddSub{
		spec:        spec,
		arrangement: arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits},
		destination: int(word & 31),
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawHalvingAddSub(form arm64RawHalvingAddSub) error {
	first, err := c.loadRawARM64VectorOperand(form.first, form.arrangement, 0, false)
	if err != nil {
		return err
	}
	second, err := c.loadRawARM64VectorOperand(form.second, form.arrangement, 0, false)
	if err != nil {
		return err
	}
	return c.lowerARM64VectorHalvingAddSubForm(
		form.spec,
		form.arrangement,
		first,
		second,
		Reg(fmt.Sprintf("V%d", form.destination)),
	)
}
