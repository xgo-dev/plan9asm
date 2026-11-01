package plan9asm

import "fmt"

// Go's _yvdppd/_yvblendpd rows encode VDPPD X and VDPPS X/Y with a
// three-byte VEX, 66, map 0F3A and imm8. Intel defines VEX.W as ignored.
// The generic decoder can instead split these bytes into legacy INC/branches.
// Recover the whole instruction, keeping physical decoding separate from
// source-layout, numerical-input and native-memory authority.
func decodedX86VEXPackedDotInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86VEXPackedDotInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86VEXPackedDotInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride, invalidPrefix, physicalSegment := false, false, false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
		case 0x65:
			segment = GS
		case 0x26, 0x2e, 0x36, 0x3e:
			physicalSegment = true
		case 0x67:
			addressOverride = true
		case 0x66, 0xf2, 0xf3, 0xf0:
			invalidPrefix = true
		default:
			if mode == 64 && code[i]&0xf0 == 0x40 {
				invalidPrefix = true
				break
			}
			goto opcode
		}
		i++
	}

opcode:
	if len(code) >= i+5 && code[i] == 0x62 && code[i+1]&7 == 3 &&
		(code[i+4] == 0x40 || code[i+4] == 0x41) {
		return Instr{}, 0, true, fmt.Errorf("packed dot products have no EVEX encoding")
	}
	if len(code) < i+4 || code[i] != 0xc4 || code[i+1]&0x1f != 3 ||
		(code[i+3] != 0x40 && code[i+3] != 0x41) {
		return Instr{}, 0, false, nil
	}
	fail := func(reason string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VEX packed dot: %s", reason)
	}
	if invalidPrefix {
		return fail("machine-invalid legacy/REX prefix before VEX")
	}
	if physicalSegment || addressOverride {
		return Instr{}, 0, true, fmt.Errorf("%w: VEX packed dot needs its original physical segment/address layout", ErrProbeNeedsContext)
	}
	p0, p1, opcode := code[i+1], code[i+2], code[i+3]
	if p1&3 != 1 {
		return fail("VEX.pp must select 66")
	}
	if opcode == 0x41 && p1&4 != 0 {
		return fail("VDPPD requires VEX.128")
	}
	modRMIndex := i + 4
	if len(code) <= modRMIndex {
		return fail("missing ModRM byte")
	}
	rExt, xExt, bExt := int(^p0>>7)&1, int(^p0>>6)&1, int(^p0>>5)&1
	secondNumber := int(^p1>>3) & 15
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8
	if mode == 32 && (rExt != 0 || xExt != 0 || bExt != 0 || secondNumber >= 8 || destinationNumber >= 8) {
		return fail("extended register in physical mode32")
	}
	bank, width := "X", 16
	if p1&4 != 0 {
		bank, width = "Y", 32
	}
	first, consumed, err := memory.vex(code[modRMIndex:], mode, bExt, xExt, segment, bank)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediateIndex := modRMIndex + consumed
	if len(code) <= immediateIndex {
		return fail("missing immediate byte")
	}
	length := immediateIndex + 1
	if length > 15 {
		return fail("instruction exceeds 15 bytes")
	}
	immediate := Operand{Kind: OpImm, Imm: int64(code[immediateIndex])}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", bank, secondNumber))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", bank, destinationNumber))}
	op := Op("VDPPS")
	if opcode == 0x41 {
		op = "VDPPD"
	}
	return Instr{
		Op: op, Args: []Operand{immediate, first, second, destination},
		Raw:        fmt.Sprintf("%s %s, %s, %s, %s", op, immediate, first, second, destination),
		x86Encoded: true, x86VectorBytes: width,
	}, length, true, nil
}
