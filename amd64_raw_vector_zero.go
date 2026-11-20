package plan9asm

import "fmt"

// The pinned x/arch decoder calls both VEX.L variants VZEROUPPER and accepts
// reserved pp/vvvv values. Decode this complete zero-operand family before
// generic fallback, binding the actual bytes rather than its printed opcode.
func decodedX86VectorZeroInstruction(code []byte, mode int) (Instr, int, bool, error) {
	i, forbidden := 0, false
	for i < len(code) {
		prefix := code[i]
		switch {
		case prefix == 0x26 || prefix == 0x2e || prefix == 0x36 || prefix == 0x3e || prefix == 0x64 || prefix == 0x65 || prefix == 0x67:
		case prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 || prefix == 0xf3 || mode == 64 && prefix >= 0x40 && prefix <= 0x4f:
			forbidden = true
		default:
			goto prefixEnd
		}
		i++
	}
prefixEnd:
	if i >= len(code) || code[i] != 0xc4 && code[i] != 0xc5 {
		return Instr{}, 0, false, nil
	}
	payload, opcode, length := i+1, i+2, i+3
	if code[i] == 0xc4 {
		payload, opcode, length = i+2, i+3, i+4
	}
	if opcode >= len(code) {
		return Instr{}, 0, false, nil
	}
	if mode == 32 && code[i+1]&0xc0 != 0xc0 {
		// These bytes are legacy LES/LDS, not a mode32 VEX prefix.
		return Instr{}, 0, false, nil
	}
	if code[opcode] != 0x77 || code[i] == 0xc4 && code[i+1]&31 != 1 {
		return Instr{}, 0, false, nil
	}
	if mode != 32 && mode != 64 || forbidden || length > 15 || code[payload]&3 != 0 || code[payload]&0x78 != 0x78 {
		return Instr{}, 0, true, fmt.Errorf("reserved raw VEX vector-zero encoding %x in mode%d", code[:length], mode)
	}
	for op, spec := range x86VectorZeroSpecs {
		if spec.vexLength == code[payload]>>2&1 {
			return Instr{Op: op, Raw: string(op)}, length, true, nil
		}
	}
	return Instr{}, 0, true, fmt.Errorf("unregistered raw VEX vector-zero length")
}
