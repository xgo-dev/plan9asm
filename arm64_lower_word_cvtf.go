package plan9asm

import "fmt"

type arm64RawCVTF struct {
	unsigned    bool
	arrangement arm64VectorArrangement
	source      int
	destination int
}

func decodeARM64RawCVTF(word uint32) (arm64RawCVTF, bool) {
	if word&0x9fbffc00 != 0x0e21d800 {
		return arm64RawCVTF{}, false
	}
	bits := 32
	if word&(1<<22) != 0 {
		bits = 64
	}
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	if bits == 64 && vectorBits == 64 {
		return arm64RawCVTF{}, false
	}
	return arm64RawCVTF{
		unsigned:    word&(1<<29) != 0,
		arrangement: arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits},
		source:      int(word>>5) & 31,
		destination: int(word & 31),
	}, true
}

func (c *arm64Ctx) lowerRawCVTF(form arm64RawCVTF) error {
	op := Op("VSCVTF")
	if form.unsigned {
		op = "VUCVTF"
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
