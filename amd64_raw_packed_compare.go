package plan9asm

import (
	"fmt"
	"strings"
)

func decodedX86PackedIntegerCompareInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched {
		return Instr{}, 0, false, nil
	}
	var op Op
	var spec amd64PackedIntegerCompareSpec
	for name, candidate := range amd64PackedIntegerCompareSpecs {
		if p.mapNumber == candidate.mapNumber && p.opcode == candidate.opcode {
			op, spec = name, candidate
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed integer compare: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.vectorLength > 2 {
		return fail("invalid prefix or vector length")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	// Intel XED leaves VEX.W and EVEX byte/word W unconstrained. D/Q
	// EVEX requires W0/W1. MASK_R reserves both destination extension bits.
	if p.evex && (!p.fixed || p.zero || p.r != 0 || spec.laneBits >= 32 && p.w != (spec.laneBits == 64)) {
		return fail("invalid EVEX fixed, zeroing, destination or width field")
	}
	if p.broadcast && (spec.laneBits < 32 || code[p.modRM]>>6 == 3) {
		return fail("broadcast requires D/Q memory source")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}
	width := []string{"X", "Y", "Z"}[p.vectorLength]
	byteWidth := 16 << p.vectorLength
	scale := byteWidth
	if p.broadcast {
		scale = spec.laneBits / 8
		op += ".BCST"
	}
	var source Operand
	var size int
	var err error
	if p.evex {
		source, size, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width, scale)
	} else {
		source, size, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	dst := Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))
	args := []Operand{source, {Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}}
	if p.evex {
		dst = Reg(fmt.Sprintf("K%d", code[p.modRM]>>3&7))
		if p.mask != 0 {
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
		}
	}
	args = append(args, Operand{Kind: OpReg, Reg: dst})
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(parts, ", ")), x86Encoded: true}, p.modRM + size, true, nil
}
