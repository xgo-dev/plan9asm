package plan9asm

import (
	"fmt"
)

// Go 1.27's _yvmaskmovpd table describes the four VEX X/Y masked load/store
// families. Opcode bit 1 selects store; W selects the D/Q integer lane.
var x86RawExplicitMaskMoveOps = map[int]Op{
	0x2c: "VMASKMOVPS",
	0x2d: "VMASKMOVPD",
	0x8c: "VPMASKMOVD",
}

func decodedX86ExplicitMaskMoveInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.evex || p.mapNumber != 2 {
		return Instr{}, 0, false, nil
	}
	// The floating store opcodes are 2E/2F, integer stores 8E/8F.
	base := p.opcode &^ 2
	op, known := x86RawExplicitMaskMoveOps[base]
	if !known {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("explicit mask move: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.vectorLength > 1 || p.w && base != 0x8c {
		return fail("invalid VEX prefix or width")
	}
	if base == 0x8c && p.w {
		op = "VPMASKMOVQ"
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if code[p.modRM]>>6 == 3 {
		return fail("explicit mask move requires a memory operand")
	}
	width := "X"
	if p.vectorLength == 1 {
		width = "Y"
	}
	memory, consumed, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))}
	mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	args := []Operand{memory, mask, data}
	if p.opcode&2 != 0 {
		args = []Operand{data, mask, memory}
	}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, args[0].String(), args[1].String(), args[2].String()),
	}, p.modRM + consumed, true, nil
}
