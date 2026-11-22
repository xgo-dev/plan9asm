package plan9asm

import "fmt"

// The Go 1.27 table has one GFNI family: multiply (0F38 CF, W0) and the
// affine/inverse pair (0F3A CE/CF, W1). Its VEX rows are X/Y; EVEX adds Z,
// masks, zeroing and, only for the affine matrix source, qword broadcast.
func decodedX86GFNIInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86GFNIInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86GFNIInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok {
		return Instr{}, 0, false, nil
	}

	var op Op
	var immediate bool
	switch {
	case p.mapNumber == 2 && p.opcode == 0xcf:
		op = "VGF2P8MULB"
	case p.mapNumber == 3 && p.opcode == 0xce:
		op, immediate = "VGF2P8AFFINEQB", true
	case p.mapNumber == 3 && p.opcode == 0xcf:
		op, immediate = "VGF2P8AFFINEINVQB", true
	default:
		return Instr{}, 0, false, nil
	}
	if p.w != immediate {
		return Instr{}, 0, true, fmt.Errorf("%s has invalid W bit", op)
	}
	if p.broadcast && !immediate {
		return Instr{}, 0, true, fmt.Errorf("%s has no broadcast form", op)
	}

	laneBits := 8
	if immediate {
		laneBits = 64
	}
	instruction, length, known, err := decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, laneBits, memory)
	if err != nil || !immediate {
		return instruction, length, known, err
	}
	return decodedX86VectorLeadingImm8(code, instruction, length)
}
