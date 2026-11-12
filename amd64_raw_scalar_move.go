package plan9asm

import (
	"fmt"
	"strings"
)

// x86RawVectorEncoding separates the shared VEX/EVEX prefix axes from a
// family's operand grammar. Register numbers are decoded (not complemented).
type x86RawVectorEncoding struct {
	modRM, mapNumber, pp, opcode int
	r, x, b, upper               int
	vectorLength, mask           int
	evex, w, zero, broadcast     bool
	fixed, addressOverride       bool
	segment                      Reg
}

func decodeX86RawVectorEncoding(code []byte) (p x86RawVectorEncoding, ok bool) {
	i := 0
	for i < len(code) {
		switch code[i] {
		case 0x64:
			p.segment = FS
		case 0x65:
			p.segment = GS
		case 0x67:
			p.addressOverride = true
		default:
			goto vector
		}
		i++
	}
	return p, false
vector:
	if i >= len(code) {
		return p, false
	}
	var bits byte
	switch code[i] {
	case 0xc5:
		if len(code) < i+3 {
			return p, false
		}
		bits = code[i+1]
		p.r, p.mapNumber, p.modRM = int(^bits>>7)&1, 1, i+3
	case 0xc4:
		if len(code) < i+4 {
			return p, false
		}
		first := code[i+1]
		bits = code[i+2]
		p.r, p.x, p.b = int(^first>>7)&1, int(^first>>6)&1, int(^first>>5)&1
		p.mapNumber, p.modRM, p.w = int(first&31), i+4, bits&0x80 != 0
	case 0x62:
		if len(code) < i+5 {
			return p, false
		}
		first, last := code[i+1], code[i+3]
		bits = code[i+2]
		p.evex, p.w, p.fixed = true, bits&0x80 != 0, bits&4 != 0
		p.r, p.x, p.b = (int(^first>>7)&1)|(int(^first>>4)&1)<<1, int(^first>>6)&1, int(^first>>5)&1
		p.mapNumber, p.modRM = int(first&15), i+5
		p.vectorLength, p.mask = int(last>>5)&3, int(last&7)
		p.zero, p.broadcast = last&0x80 != 0, last&0x10 != 0
		p.upper = (int(^last>>3) & 1) << 4
	default:
		return p, false
	}
	p.opcode, p.pp = int(code[p.modRM-1]), int(bits&3)
	p.upper |= int(^bits>>3) & 15
	if !p.evex {
		p.vectorLength = int(bits>>2) & 1
	}
	return p, true
}

// Go's _yvmovsd grammar is shared by VMOVSS and VMOVSD. Opcodes 10 and 11
// both encode three-register merges; memory forms reserve vvvv and EVEX V'.
func decodedX86ScalarMoveInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok || (p.opcode != 0x10 && p.opcode != 0x11) {
		return Instr{}, 0, false, nil
	}
	fp16 := p.evex && p.mapNumber == 5 && p.pp == 2
	if !fp16 && (p.mapNumber != 1 || (p.pp != 2 && p.pp != 3)) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar move: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	// EVEX VMOVSH is LLIG; VMOVSS/SD reserve every nonzero length.
	if (!fp16 && p.vectorLength != 0) || p.broadcast {
		return fail("scalar moves require 128-bit encoding without broadcast/rounding")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	spec := map[int]struct {
		op    Op
		bytes int
	}{2: {"VMOVSS", 4}, 3: {"VMOVSD", 8}}[p.pp]
	if fp16 {
		spec.op, spec.bytes = "VMOVSH", 2
	}
	if p.evex && (!p.fixed || p.w != (spec.bytes == 8)) {
		return fail("invalid EVEX fixed or width bit")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	registerForm := code[p.modRM]>>6 == 3
	if !registerForm && p.upper != 0 {
		return fail("memory forms reserve vvvv and V'")
	}
	store := p.opcode == 0x11
	if store && !registerForm && p.zero {
		return fail("memory stores cannot zero-mask")
	}
	regNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (regNumber >= 8 || p.upper >= 8 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	var rm Operand
	var consumed int
	var err error
	if p.evex {
		rm, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X", spec.bytes)
	} else {
		rm, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	reg := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", regNumber))}
	source, destination := rm, reg
	if store {
		source, destination = reg, rm
	}
	args := []Operand{source}
	if registerForm {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))})
	}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	op := spec.op
	if p.zero {
		op += ".Z"
	}
	printed := make([]string, len(args))
	for i := range args {
		printed[i] = args[i].String()
	}
	return Instr{
		Op: op, Args: args,
		Raw:        fmt.Sprintf("%s %s", op, strings.Join(printed, ", ")),
		x86Encoded: fp16,
	}, p.modRM + consumed, true, nil
}
