package plan9asm

import "fmt"

type arm64RawFCVTZ struct {
	unsigned    bool
	arrangement arm64VectorArrangement
	source      int
	destination int
}

func decodeARM64RawFCVTZ(word uint32) (arm64RawFCVTZ, bool) {
	masked := word & 0xbfbffc00 // Ignore Q, size, Rn, and Rd.
	if masked != 0x0ea1b800 && masked != 0x2ea1b800 {
		return arm64RawFCVTZ{}, false
	}
	elementBits := 32
	if word&(1<<22) != 0 {
		elementBits = 64
	}
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	if elementBits == 64 && vectorBits == 64 {
		return arm64RawFCVTZ{}, false
	}
	return arm64RawFCVTZ{
		unsigned:    word&(1<<29) != 0,
		arrangement: arm64VectorArrangement{elementBits: elementBits, lanes: vectorBits / elementBits},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawFCVTZ(form arm64RawFCVTZ) error {
	op := Op("VFCVTZS")
	if form.unsigned {
		op = "VFCVTZU"
	}
	arrangement := arm64VectorArrangementName(form.arrangement)
	ins := Instr{
		Op:  op,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s", op),
		Args: []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.source, arrangement))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.destination, arrangement))},
		},
	}
	ok, _, err := c.lowerARM64VectorFloatUnary(op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", op)
	}
	return err
}
