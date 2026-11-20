package plan9asm

import "fmt"

// Go 1.27's ZFRECPS and ZFRSQRTS rows each have one H/S/D three-vector
// format. Normalize raw WORD encodings to the same typed lowering as the
// corresponding named instruction.
var arm64RawSVEFloatReciprocalStep = map[uint32]Op{
	0x65001800: "ZFRECPS",
	0x65001c00: "ZFRSQRTS",
}

func decodeARM64RawSVEFloatReciprocalStep(word uint32) (Instr, bool) {
	op, ok := arm64RawSVEFloatReciprocalStep[word&0xff20fc00]
	if !ok {
		return Instr{}, false
	}
	size := word >> 22 & 3
	if size == 0 {
		return Instr{}, false
	}
	width := " HSD"[size]
	args := []Operand{
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>16&31, width))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))},
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}
