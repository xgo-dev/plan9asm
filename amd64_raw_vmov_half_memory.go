package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27 uses one _yvmovhpd operand table for all four VEX/EVEX half-vector
// memory moves. Register-only 0F 12/16 forms are the separate VMOVHLPS and
// VMOVLHPS family and are decoded before this function.
func decodedX86RawVectorHalfMemoryInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok || p.mapNumber != 1 || (p.pp != 0 && p.pp != 1) {
		return Instr{}, 0, false, nil
	}
	if p.opcode != 0x12 && p.opcode != 0x13 && p.opcode != 0x16 && p.opcode != 0x17 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("vector half memory move: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.vectorLength != 0 || p.mask != 0 || p.zero || p.broadcast {
		return fail("invalid vector length, mask, zeroing, or broadcast")
	}
	if p.evex && (!p.fixed || p.w != (p.pp == 1)) {
		return fail("invalid EVEX fixed or W bit")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if code[p.modRM]>>6 == 3 {
		if p.pp == 0 {
			return Instr{}, 0, false, nil
		}
		return fail("Go's VMOVHPD/VMOVLPD forms require memory")
	}

	var memory Operand
	var consumed int
	var err error
	if p.evex {
		memory, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X", 8)
	} else {
		memory, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	if memory.Kind != OpMem {
		return fail("expected ModRM memory operand")
	}

	op := Op("VMOVLPS")
	if p.pp == 1 {
		op = "VMOVLPD"
	}
	if p.opcode == 0x16 || p.opcode == 0x17 {
		if p.pp == 0 {
			op = "VMOVHPS"
		} else {
			op = "VMOVHPD"
		}
	}
	store := p.opcode == 0x13 || p.opcode == 0x17
	vector := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (vector >= 8 || p.upper >= 8) {
		return fail("extended vector register in 32-bit mode")
	}
	register := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", vector))}
	args := []Operand{memory, {Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}, register}
	if store {
		if p.upper != 0 {
			return fail("store reserves the VEX/EVEX vvvv field")
		}
		args = []Operand{register, memory}
	}
	printed := make([]string, len(args))
	for i, arg := range args {
		printed[i] = arg.String()
	}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s", op, strings.Join(printed, ", ")),
	}, p.modRM + consumed, true, nil
}
