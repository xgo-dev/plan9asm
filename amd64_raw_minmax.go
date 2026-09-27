package plan9asm

// VEX B/W/D ignores W. EVEX B/W also ignores W; D/Q shares an opcode with
// fixed W0/W1, and Q has no VEX encoding. The remaining operand grammar is
// shared with per-lane shifts, not inferred from the legacy disassembler.
func decodedX86PackedIntegerMinMaxInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched {
		return Instr{}, 0, false, nil
	}

	for name, spec := range amd64PackedIntegerMinMaxSpecs {
		if p.mapNumber != spec.mapNumber || p.opcode != spec.opcode {
			continue
		}
		if !p.evex && spec.laneBits == 64 {
			continue
		}
		if p.evex && spec.laneBits >= 32 && p.w != (spec.laneBits == 64) {
			continue
		}

		return decodedX86BinaryVectorOperands(code, p, mode, Op(name), spec.laneBits)
	}
	return Instr{}, 0, false, nil
}
