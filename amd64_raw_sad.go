package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27 has three vector SAD encodings: VPSADBW is 66/0F/F6 in
// VEX X/Y and EVEX X/Y/Z, VMPSADBW is VEX 66/0F3A/42 with imm8 in X/Y,
// and VDBPSADBW is the corresponding EVEX X/Y/Z immediate form with an
// optional writemask. Legacy PSADBW and MPSADBW use the x86asm path.
func decodedX86RawPackedSADInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	var op Op
	withImmediate := false
	switch {
	case p.mapNumber == 1 && p.opcode == 0xf6:
		op = "VPSADBW"
	case p.mapNumber == 3 && p.opcode == 0x42 && !p.evex:
		op, withImmediate = "VMPSADBW", true
	case p.mapNumber == 3 && p.opcode == 0x42 && p.evex:
		op, withImmediate = "VDBPSADBW", true
	default:
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("%s: %s", op, message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.w || p.vectorLength > 2 || p.evex && !p.fixed {
		return fail("invalid width or EVEX fixed bit")
	}
	if !p.evex && p.vectorLength == 2 {
		return fail("VEX does not encode Z registers")
	}
	if p.broadcast || p.mask != 0 && op != "VDBPSADBW" ||
		p.zero && (op != "VDBPSADBW" || p.mask == 0) {
		return fail("invalid broadcast, writemask or zeroing form")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended vector register in 32-bit mode")
	}

	width := [...]string{"X", "Y", "Z"}[p.vectorLength]
	var first Operand
	var consumed int
	var err error
	if p.evex {
		first, consumed, err = decodedX86EVEXRMOperand(
			code[p.modRM:], mode, p.b, p.x, p.segment, width, 16<<p.vectorLength,
		)
	} else {
		first, consumed, err = decodedX86VEXVectorRMOperand(
			code[p.modRM:], mode, p.b, p.x, p.segment, width,
		)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	length := p.modRM + consumed
	if withImmediate && len(code) <= length {
		return fail("missing imm8 byte")
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && destinationNumber >= 8 {
		return fail("extended destination register in 32-bit mode")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destinationNumber))}
	args := []Operand{first, second}
	if withImmediate {
		args = append([]Operand{{Kind: OpImm, Imm: int64(code[length])}}, args...)
		length++
	}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	if p.zero {
		op += ".Z"
	}
	parts := make([]string, len(args))
	for index, arg := range args {
		parts[index] = arg.String()
	}
	return Instr{
		Op:         op,
		Args:       args,
		Raw:        fmt.Sprintf("%s %s", op, strings.Join(parts, ", ")),
		x86Encoded: true,
	}, length, true, nil
}
