package plan9asm

import (
	"fmt"
	"strings"
)

// Decode the shared two-source vector grammar after the family has selected
// its operation and validated generation/W. The memory source is first in
// Plan 9 order; EVEX masks and broadcast retain their typed semantics.
func decodedX86BinaryVectorOperands(code []byte, p x86RawVectorEncoding, mode int, op Op, laneBits int) (Instr, int, bool, error) {
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("%s: %s", op, message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.vectorLength > 2 || p.evex && !p.fixed {
		return fail("invalid prefix, fixed bit or vector length")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires K1-K7")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if p.broadcast && (laneBits < 32 || code[p.modRM]>>6 == 3) {
		return fail("broadcast requires D/Q memory source")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}

	width := []string{"X", "Y", "Z"}[p.vectorLength]
	scale := 16 << p.vectorLength
	if p.broadcast {
		scale = laneBits / 8
		op += ".BCST"
	}
	if p.zero {
		op += ".Z"
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

	args := []Operand{
		source,
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))},
	}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	destination := int(code[p.modRM]>>3&7) + p.r*8
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destination))})

	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = arg.String()
	}
	instruction := Instr{
		Op:         op,
		Args:       args,
		Raw:        fmt.Sprintf("%s %s", op, strings.Join(parts, ", ")),
		x86Encoded: true,
	}
	return instruction, p.modRM + size, true, nil
}
