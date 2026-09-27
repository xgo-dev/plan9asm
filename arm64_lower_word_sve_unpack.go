package plan9asm

import "fmt"

// The four SVE widening-unpack operations use one grammar. The size field
// selects B-to-H, H-to-S, or S-to-D; opcode bits select sign and half.
func decodeARM64RawSVEUnpack(word uint32) (Instr, bool) {
	if word&0xff3cfc00 != 0x05303800 {
		return Instr{}, false
	}
	width := int(word>>22) & 3
	if width == 0 {
		return Instr{}, false
	}
	opcode := int(word>>16) & 3
	operations := [...]Op{"ZSUNPKLO", "ZSUNPKHI", "ZUUNPKLO", "ZUUNPKHI"}
	arrangements := [...]string{"", "B", "H", "S", "D"}
	source := Reg(fmt.Sprintf("Z%d.%s", word>>5&31, arrangements[width]))
	destination := Reg(fmt.Sprintf("Z%d.%s", word&31, arrangements[width+1]))
	return Instr{
		Op:   operations[opcode],
		Args: []Operand{{Kind: OpReg, Reg: source}, {Kind: OpReg, Reg: destination}},
		Raw:  fmt.Sprintf("WORD $%#08x", word),
	}, true
}
