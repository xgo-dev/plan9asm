package plan9asm

import "fmt"

type arm64RawUZP struct {
	op          Op
	arrangement arm64VectorArrangement
	destination int
	first       int
	second      int
}

func decodeARM64RawUZP(word uint32) (arm64RawUZP, bool) {
	form := arm64RawUZP{}
	switch word & 0xbf20fc00 {
	case 0x0e001800:
		form.op = "VUZP1"
	case 0x0e005800:
		form.op = "VUZP2"
	default:
		return arm64RawUZP{}, false
	}
	size := int(word>>22) & 3
	vectorBits := 64
	if word&(1<<30) != 0 {
		vectorBits = 128
	}
	if size == 3 && vectorBits != 128 {
		return arm64RawUZP{}, false
	}
	bits := 8 << size
	form.arrangement = arm64VectorArrangement{elementBits: bits, lanes: vectorBits / bits}
	form.destination = int(word & 31)
	form.first = int(word>>5) & 31
	form.second = int(word>>16) & 31
	return form, true
}

func (c *arm64Ctx) lowerRawUZP(form arm64RawUZP) error {
	arrangement := arm64VectorArrangementName(form.arrangement)
	reg := func(index int) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", index, arrangement))}
	}
	// The existing Plan 9 lowerer takes Vm, Vn, Vd; raw encoding fields are
	// named according to the architectural Vd, Vn, Vm order.
	ins := Instr{
		Op:  form.op,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s", form.op),
		Args: []Operand{
			reg(form.second),
			reg(form.first),
			reg(form.destination),
		},
	}
	ok, _, err := c.lowerARM64VectorPermute(form.op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", form.op)
	}
	return err
}
