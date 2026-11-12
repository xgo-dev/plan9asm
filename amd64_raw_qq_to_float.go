package plan9asm

// x86RawQQToFloatForm maps opcode and mandatory prefix to the Go 1.27
// QWORD-to-PS/PD optabs. PS narrows the Y/Z destination by one vector width.
func x86RawQQToFloatForm(p x86RawVectorEncoding) (base Op, narrow bool, ok bool) {
	switch {
	case p.opcode == 0x5b && p.pp == 0:
		return "VCVTQQ2PS", true, true
	case p.opcode == 0x7a && p.pp == 3:
		return "VCVTUQQ2PS", true, true
	case p.opcode == 0xe6 && p.pp == 2:
		return "VCVTQQ2PD", false, true
	case p.opcode == 0x7a && p.pp == 2:
		return "VCVTUQQ2PD", false, true
	default:
		return "", false, false
	}
}

// decodedX86RawQQToFloatInstruction handles all four EVEX QWORD-to-PS/PD
// conversion families, including every X/Y/Z, K-mask, broadcast, and
// maximum-width embedded-rounding form.
func decodedX86RawQQToFloatInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || !p.w || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	if _, _, known := x86RawQQToFloatForm(p); !known {
		return Instr{}, 0, false, nil
	}
	return decodedX86PackedNumericConversionInstruction(code, mode)
}
