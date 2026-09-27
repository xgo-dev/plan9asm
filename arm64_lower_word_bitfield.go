package plan9asm

import "fmt"

type arm64RawBitfield struct {
	op          Op
	width       int
	immr        int
	imms        int
	source      int
	destination int
}

func decodeARM64RawBitfield(word uint32) (arm64RawBitfield, bool) {
	if word&0x1f800000 != 0x13000000 {
		return arm64RawBitfield{}, false
	}
	var op Op
	switch (word >> 29) & 3 {
	case 0:
		op = "SBFM"
	case 1:
		op = "BFM"
	case 2:
		op = "UBFM"
	default:
		return arm64RawBitfield{}, false
	}
	width := 32
	n := word&(1<<22) != 0
	if word&(1<<31) != 0 {
		width = 64
		if !n {
			return arm64RawBitfield{}, false
		}
	} else if n {
		return arm64RawBitfield{}, false
	}
	immr := int(word>>16) & 63
	imms := int(word>>10) & 63
	if width == 32 && (immr >= 32 || imms >= 32) {
		return arm64RawBitfield{}, false
	}
	return arm64RawBitfield{
		op:          op,
		width:       width,
		immr:        immr,
		imms:        imms,
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawBitfield(form arm64RawBitfield) error {
	// Rd=31 is WZR/XZR for bitfield instructions, so the result is discarded.
	if form.destination == 31 {
		return nil
	}
	source := Reg(fmt.Sprintf("R%d", form.source))
	if form.source == 31 {
		source = ZR
	}
	destination := Reg(fmt.Sprintf("R%d", form.destination))
	var alias Op
	var lsb, width int
	if form.imms >= form.immr {
		lsb = form.immr
		width = form.imms - form.immr + 1
		switch form.op {
		case "SBFM":
			alias = "SBFX"
		case "BFM":
			alias = "BFXIL"
		case "UBFM":
			alias = "UBFX"
		}
	} else {
		lsb = form.width - form.immr
		width = form.imms + 1
		switch form.op {
		case "SBFM":
			alias = "SBFIZ"
		case "BFM":
			alias = "BFI"
		case "UBFM":
			alias = "UBFIZ"
		}
	}
	if form.width == 32 {
		alias += "W"
	}
	ins := Instr{
		Op:  alias,
		Raw: fmt.Sprintf("decoded ARM64 WORD as %s alias %s", form.op, alias),
		Args: []Operand{
			{Kind: OpImm, Imm: int64(lsb)},
			{Kind: OpReg, Reg: source},
			{Kind: OpImm, Imm: int64(width)},
			{Kind: OpReg, Reg: destination},
		},
	}
	return c.lowerBitfield(alias, ins)
}
