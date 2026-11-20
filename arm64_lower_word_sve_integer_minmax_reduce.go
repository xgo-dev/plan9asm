package plan9asm

import "fmt"

// SVE's four predicated integer min/max reductions share one encoding
// grammar. The opcode chooses signedness and min/max; size chooses B/H/S/D.
func decodeARM64RawSVEIntegerMinMaxReduction(word uint32) (Instr, bool) {
	if word&0xff30e000 != 0x04002000 {
		return Instr{}, false
	}
	opcode := int(word>>16) & 15
	if opcode < 8 || opcode > 11 {
		return Instr{}, false
	}
	width := int(word>>22) & 3
	operations := [...]string{"ZSMAXV", "ZUMAXV", "ZSMINV", "ZUMINV"}
	arrangements := [...]string{"B", "H", "S", "D"}
	op := Op(operations[opcode-8] + arrangements[width])
	source := Reg(fmt.Sprintf("Z%d.%s", word>>5&31, arrangements[width]))
	predicate := Reg(fmt.Sprintf("P%d", word>>10&7))
	destination := Reg(fmt.Sprintf("V%d", word&31))
	return Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: source},
			{Kind: OpReg, Reg: predicate},
			{Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("WORD $%#08x", word),
	}, true
}
