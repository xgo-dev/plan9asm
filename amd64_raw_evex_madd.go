package plan9asm

import (
	"fmt"
)

// decodedX86EVEXPackedMADDInstruction covers the EVEX rows of Go's
// _yvandnpd optab shared by VPMADDUBSW and VPMADDWD. Neither row permits
// EVEX.b broadcasting, but both permit K masks and zeroing at X/Y/Z widths.
func decodedX86EVEXPackedMADDInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86EVEXPackedMADDInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86EVEXPackedMADDInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	op := map[[2]int]Op{
		{1, 0xf5}: "VPMADDWD",
		{2, 0x04}: "VPMADDUBSW",
	}[[2]int{p.mapNumber, p.opcode}]
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX packed multiply-add: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.broadcast || p.addressOverride || p.vectorLength > 2 {
		return fail("invalid EVEX fixed, width, broadcast, address, or vector-length bits")
	}
	// Both opcode-specific ISA rows are WIG. Full validated physical bytes,
	// including mode32 masks, use the common private decoder producer.
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, 16, memory)
}
