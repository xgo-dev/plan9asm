package plan9asm

import "fmt"

// decodedX86RawMaskBlendInstruction covers all six Go 1.27 _yvblendmpd
// operations across EVEX X/Y/Z, optional K mask and zeroing, and permitted
// D/Q scalar broadcasts. The shared typed operand decoder handles ModRM/SIB.
func decodedX86RawMaskBlendInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	var op Op
	var laneBits int
	switch p.opcode {
	case 0x65:
		if p.w {
			op, laneBits = "VBLENDMPD", 64
		} else {
			op, laneBits = "VBLENDMPS", 32
		}
	case 0x64:
		if p.w {
			op, laneBits = "VPBLENDMQ", 64
		} else {
			op, laneBits = "VPBLENDMD", 32
		}
	case 0x66:
		if p.w {
			op, laneBits = "VPBLENDMW", 16
		} else {
			op, laneBits = "VPBLENDMB", 8
		}
	default:
		return Instr{}, 0, false, nil
	}
	if mode == 32 && p.mask != 0 {
		return Instr{}, 0, true, fmt.Errorf("386 masked %s exceeds Go's three-operand frontend", op)
	}
	return decodedX86BinaryVectorOperands(code, p, mode, op, laneBits)
}
