package plan9asm

import "fmt"

// VEX variable blends encode the mask register in imm8[7:4], not an ordinary
// immediate. Intel's AVX/AVX2 tables specify 66.0F3A.W0, X/Y widths and no
// EVEX forms. The low nibble is ignored; in 32-bit mode bit 7 is also ignored.
func decodedX86VariableBlendInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 3 {
		return Instr{}, 0, false, nil
	}
	var op Op
	for candidate, spec := range amd64VariableBlendSpecs {
		if spec.vector && spec.opcode == p.opcode {
			op = candidate
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("variable blend: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.w || p.pp != 1 {
		return fail("requires VEX.128/256.66.0F3A.W0")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 {
		if p.r != 0 || p.x != 0 {
			return fail("legacy LES encoding is not a 32-bit VEX instruction")
		}
		// Three-byte VEX ignores these high register selectors outside
		// 64-bit mode, independently of the imm8 mask-register selector.
		p.b = 0
		p.upper &= 7
	}
	prefix := "X"
	if p.vectorLength != 0 {
		prefix = "Y"
	}
	source, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, prefix)
	if err != nil {
		return Instr{}, 0, true, err
	}
	immediate := p.modRM + size
	if len(code) <= immediate {
		return fail("missing mask-register selector byte")
	}
	mask := int(code[immediate] >> 4)
	if mode == 32 {
		mask &= 7
	}
	reg := func(index int) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, index))}
	}
	args := []Operand{reg(mask), source, reg(p.upper), reg(int(code[p.modRM]>>3&7) + p.r*8)}
	return Instr{
		Op: op, Args: args,
		Raw: fmt.Sprintf("%s %s, %s, %s, %s", op, args[0].String(), source.String(), args[2].String(), args[3].String()),
	}, immediate + 1, true, nil
}
