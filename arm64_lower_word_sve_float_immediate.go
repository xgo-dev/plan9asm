package plan9asm

import (
	"fmt"
	"math"
)

// Go 1.27's ZFDUP/ZFCPY rows share an 8-bit floating immediate and H/S/D
// elements. ZFCPY adds P0..P15/M. LLVM's FMOV spellings are aliases.
func decodeARM64RawSVEFloatImmediate(word uint32) (Instr, bool) {
	op := Op("ZFDUP")
	switch {
	case word&0xff3fe000 == 0x2539c000:
	case word&0xff30e000 == 0x0510c000:
		op = "ZFCPY"
	default:
		return Instr{}, false
	}
	width := map[uint32]string{1: "H", 2: "S", 3: "D"}[word>>22&3]
	if width == "" {
		return Instr{}, false
	}
	immediate := byte(word >> 5)
	value := arm64ExpandedFloatImmediate(immediate)
	destination := int(word) & 31
	args := []Operand{{Kind: OpImm, Imm: int64(math.Float64bits(value)), ImmIsFloat: true}}
	if op == "ZFCPY" {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", word>>16&15))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", destination, width))})
	return Instr{
		Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}
