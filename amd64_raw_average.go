package plan9asm

import "fmt"

// The complete VEX/EVEX physical decoder is the only producer of the private
// marker which distinguishes raw mode32 masks from named Go's operand limit.
func decodedX86PackedAverageInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86PackedAverageInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86PackedAverageInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.pp != 1 || p.opcode != 0xe0 && p.opcode != 0xe3 {
		return Instr{}, 0, false, nil
	}
	if p.broadcast {
		return Instr{}, 0, true, fmt.Errorf("packed average has no broadcast or rounding encoding")
	}
	op, bits := Op("VPAVGB"), 8
	if p.opcode == 0xe3 {
		op, bits = "VPAVGW", 16
	}
	// WIG is a hardware property; the named Go encoder always emits W0.
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, bits, memory)
}
