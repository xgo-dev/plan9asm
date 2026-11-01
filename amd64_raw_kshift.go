package plan9asm

import "fmt"

// Go 1.27 _ykshiftlb uses opcode 30/31 for right and 32/33 for left;
// VEX.W distinguishes B/W or D/Q at each opcode.
var x86RawMaskShiftOps = [4][2]Op{
	{"KSHIFTRB", "KSHIFTRW"},
	{"KSHIFTRD", "KSHIFTRQ"},
	{"KSHIFTLB", "KSHIFTLW"},
	{"KSHIFTLD", "KSHIFTLQ"},
}

func decodedX86RawMaskShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || p.evex || p.mapNumber != 3 || p.pp != 1 || p.opcode < 0x30 || p.opcode > 0x33 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("mask shift: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.vectorLength != 0 || p.upper != 0 || p.r != 0 || p.b != 0 || p.x != 0 {
		return fail("invalid reserved VEX bit")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	if modRM>>6 != 3 {
		return fail("KSHIFT requires a K-register source")
	}
	if len(code) <= p.modRM+1 {
		return fail("missing imm8 shift count")
	}
	w := 0
	if p.w {
		w = 1
	}
	op := x86RawMaskShiftOps[p.opcode-0x30][w]
	count := code[p.modRM+1]
	source := modRM & 7
	destination := modRM >> 3 & 7
	args := []Operand{
		{Kind: OpImm, Imm: int64(count)},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", source))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", destination))},
	}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s $%d, K%d, K%d", op, count, source, destination),
	}, p.modRM + 2, true, nil
}
