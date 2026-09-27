package plan9asm

import "fmt"

// Go 1.27's _yvpinsrb table has one EVEX.128 row for each scalar width.
// VEX forms use decodedX86VPINSRInstruction; the EVEX row extends X
// base/destination registers to X31 and scales disp8 by the scalar width.
func decodedX86EVEXVPINSRInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	op := Op("")
	laneBytes := 0
	switch {
	case p.mapNumber == 3 && p.opcode == 0x20 && !p.w:
		op, laneBytes = "VPINSRB", 1
	case p.mapNumber == 1 && p.opcode == 0xc4 && !p.w:
		op, laneBytes = "VPINSRW", 2
	case p.mapNumber == 3 && p.opcode == 0x22 && !p.w:
		op, laneBytes = "VPINSRD", 4
	case p.mapNumber == 3 && p.opcode == 0x22 && p.w:
		op, laneBytes = "VPINSRQ", 8
	default:
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("raw EVEX %s: %s", op, message)
	}
	if mode != 64 {
		return fail("Go assembler exposes this EVEX form only on amd64")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if !p.fixed || p.vectorLength != 0 || p.mask != 0 || p.zero || p.broadcast {
		return fail("invalid EVEX fixed, length, mask, zeroing or broadcast bits")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	source, consumed, err := decodedX86RMSource(
		code[p.modRM:], mode, p.b, p.x, p.segment, laneBytes,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediateIndex := p.modRM + consumed
	if len(code) <= immediateIndex {
		return fail("missing immediate byte")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	base := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", int(modRM>>3&7)+p.r*8))}
	args := []Operand{immediate, source, base, destination}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s, %s, %s, %s", op, immediate.String(), source.String(), base.String(), destination.String()),
	}, immediateIndex + 1, true, nil
}
