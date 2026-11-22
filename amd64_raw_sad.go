package plan9asm

import "fmt"

// Go 1.27 has three vector SAD encodings: VPSADBW is 66/0F/F6 in
// VEX X/Y and EVEX X/Y/Z, VMPSADBW is VEX 66/0F3A/42 with imm8 in X/Y,
// and VDBPSADBW is the corresponding EVEX X/Y/Z immediate form with an
// optional writemask. Legacy PSADBW and MPSADBW use the x86asm path.
func decodedX86RawPackedSADInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86RawPackedSADInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86RawPackedSADInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
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
	if p.w && op == "VDBPSADBW" {
		return Instr{}, 0, true, fmt.Errorf("%s: invalid W bit", op)
	}
	if !p.evex && p.vectorLength == 2 {
		return Instr{}, 0, true, fmt.Errorf("%s: VEX does not encode Z registers", op)
	}
	if p.broadcast || p.mask != 0 && op != "VDBPSADBW" {
		return Instr{}, 0, true, fmt.Errorf("%s: invalid broadcast or writemask form", op)
	}
	ins, length, known, err := decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, 16, memory)
	if err != nil || !withImmediate {
		return ins, length, known, err
	}
	return decodedX86VectorLeadingImm8(code, ins, length)
}
