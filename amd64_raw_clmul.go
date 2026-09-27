package plan9asm

import "fmt"

// decodedX86RawCLMULInstruction covers Go's complete PCLMULQDQ and
// VPCLMULQDQ tables: legacy X, VEX X/Y, and EVEX X/Y/Z, each with imm8.
// Go's vector form has no mask, broadcast, or W1 encoding.
func decodedX86RawCLMULInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if matched && p.mapNumber == 3 && p.pp == 1 && p.opcode == 0x44 {
		return decodedX86RawVectorCLMULInstruction(code, mode, p)
	}
	return decodedX86RawLegacyCLMULInstruction(code, mode)
}

func decodedX86RawVectorCLMULInstruction(code []byte, mode int, p x86RawVectorEncoding) (Instr, int, bool, error) {
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VPCLMULQDQ: %s", message)
	}
	if mode != 64 {
		return fail("Go's four-operand vector form requires amd64")
	}
	if p.addressOverride || p.w || p.vectorLength > 2 ||
		p.evex && (!p.fixed || p.mask != 0 || p.zero || p.broadcast) {
		return fail("invalid prefix, mask, broadcast or vector length")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = decodedX86EVEXRMOperand(
			code[p.modRM:], mode, p.b, p.x, p.segment, width, 16<<p.vectorLength,
		)
	} else {
		source, consumed, err = decodedX86VEXVectorRMOperand(
			code[p.modRM:], mode, p.b, p.x, p.segment, width,
		)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	immIndex := p.modRM + consumed
	if len(code) <= immIndex {
		return fail("missing imm8")
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(modRM>>3&7)+p.r*8))}
	imm := Operand{Kind: OpImm, Imm: int64(code[immIndex])}
	return Instr{
		Op:   "VPCLMULQDQ",
		Args: []Operand{imm, source, second, destination},
		Raw:  fmt.Sprintf("VPCLMULQDQ %s, %s, %s, %s", imm.String(), source.String(), second.String(), destination.String()),
	}, immIndex + 1, true, nil
}

func decodedX86RawLegacyCLMULInstruction(code []byte, mode int) (Instr, int, bool, error) {
	i := 0
	segment := Reg("")
	addressOverride := false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
		case 0x65:
			segment = GS
		case 0x67:
			addressOverride = true
		default:
			goto encoding
		}
		i++
	}

encoding:
	if len(code) <= i || code[i] != 0x66 {
		return Instr{}, 0, false, nil
	}
	i++
	rex := byte(0)
	if i < len(code) && code[i]&0xf0 == 0x40 {
		rex = code[i]
		i++
	}
	if len(code) < i+3 || code[i] != 0x0f || code[i+1] != 0x3a || code[i+2] != 0x44 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("PCLMULQDQ: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if addressOverride || mode == 32 && rex != 0 {
		return fail("address override or REX prefix is invalid")
	}
	modRMIndex := i + 3
	if len(code) <= modRMIndex {
		return fail("missing ModRM byte")
	}
	modRM := code[modRMIndex]
	destinationNumber := int(modRM>>3&7) + int(rex>>2&1)*8
	if mode == 32 && destinationNumber >= 8 {
		return fail("high X register is unavailable in 386 mode")
	}
	source, consumed, err := decodedX86VEXVectorRMOperand(
		code[modRMIndex:], mode, int(rex&1), int(rex>>1&1), segment, "X",
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immIndex := modRMIndex + consumed
	if len(code) <= immIndex {
		return fail("missing imm8")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	imm := Operand{Kind: OpImm, Imm: int64(code[immIndex])}
	return Instr{
		Op:   "PCLMULQDQ",
		Args: []Operand{imm, source, destination},
		Raw:  fmt.Sprintf("PCLMULQDQ %s, %s, %s", imm.String(), source.String(), destination.String()),
	}, immIndex + 1, true, nil
}
