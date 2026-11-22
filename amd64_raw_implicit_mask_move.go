package plan9asm

import "fmt"

// MASKMOVDQU and VMASKMOVDQU encode data in ModRM.reg and the
// mask in ModRM.r/m. Neither form encodes the DI memory destination.
func decodedX86ImplicitVectorMaskMove(code []byte, mode int) (Instr, int, bool, error) {
	op, modRM, reg, rm := Op("MASKMOVDQU"), 3, 0, 0
	var segment byte
	addressOverride := false
	fail := func(reason string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("implicit vector mask store: %s", reason)
	}
	if p, vector := decodeX86RawVectorEncoding(code); vector {
		if p.evex || p.mapNumber != 1 || p.opcode != 0xf7 {
			return Instr{}, 0, false, nil
		}
		// W is ignored, while the encoded vvvv field is reserved and
		// must be all ones (zero after complementing).
		if p.pp != 1 || p.vectorLength != 0 || p.upper != 0 {
			return fail("invalid VEX prefix")
		}
		if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0) {
			return fail("extended VEX register encoding in 32-bit mode")
		}
		op, modRM, reg, rm = "VMASKMOVDQU", p.modRM, p.r, p.b
		switch p.segment {
		case FS:
			segment = 0x64
		case GS:
			segment = 0x65
		}
		addressOverride = p.addressOverride
	} else {
		// The generic decoder keeps legacy address-size overrides unbound.
		// Only the exact default-address SSE encoding enters this path.
		if len(code) < 3 || code[0] != 0x66 {
			return Instr{}, 0, false, nil
		}
		if mode == 64 && code[1]&0xf0 == 0x40 {
			reg, rm, modRM = int(code[1]>>2&1), int(code[1]&1), modRM+1
		}
		if len(code) < modRM || code[modRM-2] != 0x0f || code[modRM-1] != 0xf7 {
			return Instr{}, 0, false, nil
		}
	}
	if len(code) <= modRM || code[modRM]>>6 != 3 {
		return fail("expected a register ModRM")
	}
	mask := Reg(fmt.Sprintf("X%d", rm*8+int(code[modRM]&7)))
	data := Reg(fmt.Sprintf("X%d", reg*8+int(code[modRM]>>3&7)))
	ins := Instr{
		Op:   op,
		Args: []Operand{{Kind: OpReg, Reg: mask}, {Kind: OpReg, Reg: data}},
		Raw:  fmt.Sprintf("%s %s, %s", op, mask, data),

		x86Encoded:       true,
		x86SegmentPrefix: segment,
	}
	if addressOverride {
		ins.x86AddressBits = mode / 2
		ins.x86UnboundAddressOverride = true
	}
	return ins, modRM + 1, true, nil
}
