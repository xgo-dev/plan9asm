package plan9asm

// The zero value retains the raw source decoder's layout restrictions. Only
// original native byte observers select physicalPC: they observe whole native
// instruction boundaries and discards these operands. A physical RIP+disp32
// is not a source symbol, bounded literal, numerical value, or read permission.
type x86RawMemoryDecoder struct {
	physicalPC bool
}

func (d x86RawMemoryDecoder) vexTransfer(code []byte, mode, bExt, xExt int, segment Reg, vector bool) (Operand, int, error) {
	if len(code) == 0 || code[0]>>6 == 3 || !d.physicalPC {
		return decodedX86VEXRMOperand(code, mode, bExt, xExt, segment, vector)
	}
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, 1, true)
}

func (d x86RawMemoryDecoder) scalar(code []byte, mode, bExt, xExt int, segment Reg, width int) (Operand, int, error) {
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, width, d.physicalPC)
}

func (d x86RawMemoryDecoder) evex(code []byte, mode, bExt, xExt int, segment Reg, bank string, scale int) (Operand, int, error) {
	if len(code) == 0 || code[0]>>6 == 3 {
		return decodedX86EVEXRMOperand(code, mode, bExt, xExt, segment, bank, scale)
	}
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, scale, d.physicalPC)
}

func (d x86RawMemoryDecoder) vex(code []byte, mode, bExt, xExt int, segment Reg, bank string) (Operand, int, error) {
	if len(code) == 0 || code[0]>>6 == 3 {
		return decodedX86VEXVectorRMOperand(code, mode, bExt, xExt, segment, bank)
	}
	return decodedX86RMSourceWithPC(code, mode, bExt, xExt, segment, 1, d.physicalPC)
}
