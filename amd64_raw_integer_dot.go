package plan9asm

import "fmt"

func decodedX86IntegerPackedDotInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.evex && p.pp == 2 {
		return Instr{}, 0, false, nil // BF16 owns EVEX.F3, not integer VNNI.
	}
	var op Op
	for name, spec := range amd64PackedDotProductSpecs {
		if !spec.bfloat && int(spec.opcode) == p.opcode {
			op = name
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	if p.w {
		return Instr{}, 0, true, fmt.Errorf("integer dot-product encoding requires W0")
	}
	ins, size, known, err := decodedX86BinaryVectorOperands(code, p, mode, op, 32)
	if err != nil || !known {
		return ins, size, known, err
	}
	if size > 15 {
		return Instr{}, 0, true, fmt.Errorf("integer dot-product instruction exceeds 15 bytes")
	}
	ins.x86VectorBytes = 16 << p.vectorLength
	ins.x86PackedDotEncoding = x86RawPackedDotVEX
	if p.evex {
		ins.x86PackedDotEncoding = x86RawPackedDotEVEX
	}
	return ins, size, true, nil
}
