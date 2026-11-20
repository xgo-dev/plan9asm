package plan9asm

import "fmt"

// SVE signed/unsigned min/max share four opcodes and four element widths.
// Go 1.27 exposes both the predicated register and destructive immediate
// forms; decode either into the same typed named-instruction lowerer.
func decodeARM64RawSVEIntegerMinMax(word uint32) (Instr, bool) {
	predicated := word&0xff30e000 == 0x04000000
	immediate := word&0xff3ce000 == 0x2528c000
	if !predicated && !immediate {
		return Instr{}, false
	}

	var opcode int
	if predicated {
		opcode = int(word>>16) & 15
		if opcode < 8 || opcode > 11 {
			return Instr{}, false
		}
		opcode -= 8
	} else {
		opcode = int(word>>16) & 3
	}
	operations := [...]Op{"ZSMAX", "ZUMAX", "ZSMIN", "ZUMIN"}
	op := operations[opcode]
	arrangements := [...]string{"B", "H", "S", "D"}
	width := int(word>>22) & 3
	destination := Reg(fmt.Sprintf("Z%d.%s", word&31, arrangements[width]))

	var args []Operand
	if predicated {
		second := Reg(fmt.Sprintf("Z%d.%s", word>>5&31, arrangements[width]))
		predicate := Reg(fmt.Sprintf("P%d.M", word>>10&7))
		args = []Operand{
			{Kind: OpReg, Reg: second},
			{Kind: OpReg, Reg: destination},
			{Kind: OpReg, Reg: predicate},
			{Kind: OpReg, Reg: destination},
		}
	} else {
		value := int64(uint8(word >> 5))
		if opcode == 0 || opcode == 2 {
			value = int64(int8(word >> 5))
		}
		args = []Operand{
			{Kind: OpImm, Imm: value},
			{Kind: OpReg, Reg: destination},
			{Kind: OpReg, Reg: destination},
		}
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
}
