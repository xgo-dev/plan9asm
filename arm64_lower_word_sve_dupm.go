package plan9asm

import "fmt"

// ZDUPM shares the thirteen-bit logical-immediate grammar with SVE bitwise
// instructions. The element width is encoded by the immediate itself.
func decodeARM64RawSVEDupM(word uint32) (Instr, bool) {
	if word&0xfffc0000 != 0x05c00000 {
		return Instr{}, false
	}
	elementBits, immediate, ok := decodeARM64SVELogicalImmediate(int(word>>5) & 0x1fff)
	if !ok {
		return Instr{}, false
	}
	width := map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[elementBits]
	destination := word & 31
	return Instr{
		Op: "ZDUPM",
		Args: []Operand{
			{Kind: OpImm, Imm: int64(immediate)},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", destination, width))},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}
