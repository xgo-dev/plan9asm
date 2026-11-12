package plan9asm

import "fmt"

type arm64RawLogical struct {
	op          Op
	arrangement arm64VectorArrangement
	first       int
	second      int
	destination int
}

func decodeARM64RawLogical(word uint32) (arm64RawLogical, bool) {
	var op Op
	switch word & 0xbfe0fc00 { // Ignore Q, Rm, Rn, and Rd.
	case 0x0e201c00:
		op = "VAND"
	case 0x0e601c00:
		op = "VBIC"
	case 0x0ea01c00:
		op = "VORR"
	case 0x0ee01c00:
		op = "VORN"
	case 0x2e201c00:
		op = "VEOR"
	case 0x2e601c00:
		op = "VBSL"
	case 0x2ea01c00:
		op = "VBIT"
	case 0x2ee01c00:
		op = "VBIF"
	default:
		return arm64RawLogical{}, false
	}
	lanes := 8
	if word&(1<<30) != 0 {
		lanes = 16
	}
	return arm64RawLogical{
		op:          op,
		arrangement: arm64VectorArrangement{elementBits: 8, lanes: lanes},
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawLogical(form arm64RawLogical) error {
	arrangement := arm64VectorArrangementName(form.arrangement)
	ins := Instr{
		Op:  form.op,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s", form.op),
		Args: []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.second, arrangement))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.first, arrangement))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("V%d.%s", form.destination, arrangement))},
		},
	}
	ok, _, err := c.lowerARM64VectorLogical(form.op, ins)
	if !ok && err == nil {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", form.op)
	}
	return err
}
