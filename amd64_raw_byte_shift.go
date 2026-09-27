package plan9asm

import "fmt"

// decodedX86RawVectorByteShiftInstruction covers Go's VPSLLDQ/VPSRLDQ
// _yvpslldq table: VEX X/Y register forms and EVEX X/Y/Z register or memory
// forms, all with an imm8. ModRM.reg is the opcode extension (/7 or /3),
// while VEX.vvvv or EVEX.vvvvv names the destination.
func decodedX86RawVectorByteShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.pp != 1 || p.opcode != 0x73 {
		return Instr{}, 0, false, nil
	}
	if len(code) <= p.modRM {
		return Instr{}, 0, true, fmt.Errorf("vector byte shift: missing ModRM byte")
	}
	group := int(code[p.modRM]>>3) & 7
	if group != 3 && group != 7 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("vector byte shift: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride || p.w || p.r != 0 || p.vectorLength > 2 ||
		p.evex && !p.fixed || p.mask != 0 || p.zero || p.broadcast {
		return fail("invalid prefix, mask or vector length")
	}
	registerSource := code[p.modRM]>>6 == 3
	if !p.evex && !registerSource {
		return fail("VEX byte shift requires a register source")
	}
	if mode == 32 && (p.upper >= 8 || registerSource && (p.b != 0 || p.x != 0)) {
		return fail("extended vector register in 32-bit mode")
	}
	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width, 16<<p.vectorLength)
	} else {
		source, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	immIndex := p.modRM + consumed
	if len(code) <= immIndex {
		return fail("missing imm8")
	}
	op := Op("VPSRLDQ")
	if group == 7 {
		op = "VPSLLDQ"
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	args := []Operand{{Kind: OpImm, Imm: int64(code[immIndex])}, source, destination}
	return Instr{
		Op: op, Args: args,
		Raw: fmt.Sprintf("%s %s, %s, %s", op, args[0].String(), source.String(), destination.String()),
	}, immIndex + 1, true, nil
}
