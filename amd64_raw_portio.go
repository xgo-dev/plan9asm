package plan9asm

import "fmt"

// decodedX86ScalarPortIOInstruction covers Go's complete yin table: input
// and output, byte/word/long, with either an immediate port or implicit DX.
// x/arch's GoSyntax prints the architectural accumulator and DX operands,
// whereas Go's assembler source syntax omits both. Its old decoder also calls
// the byte encodings INL/OUTL. Decode these small fixed forms from the opcode.
func decodedX86ScalarPortIOInstruction(code []byte) (Instr, int, bool, error) {
	if len(code) == 0 {
		return Instr{}, 0, false, nil
	}
	index := 0
	word := false
	if code[index] == 0x66 {
		word = true
		index++
		if len(code) == index {
			return Instr{}, 0, false, nil
		}
	}
	opcode := code[index]
	if opcode < 0xe4 || (opcode > 0xe7 && opcode < 0xec) || opcode > 0xef {
		return Instr{}, 0, false, nil
	}
	input := opcode == 0xe4 || opcode == 0xe5 || opcode == 0xec || opcode == 0xed
	byteWidth := opcode&1 == 0
	name := "OUT"
	if input {
		name = "IN"
	}
	width := "L"
	if byteWidth {
		width = "B"
	} else if word {
		width = "W"
	}
	index++
	var args []Operand
	if opcode >= 0xe4 && opcode <= 0xe7 {
		if len(code) == index {
			return Instr{}, 0, true, fmt.Errorf("missing immediate port byte")
		}
		args = []Operand{{Kind: OpImm, Imm: int64(code[index])}}
		index++
	}
	op := Op(name + width)
	raw := string(op)
	if len(args) != 0 {
		raw = fmt.Sprintf("%s $%d", op, args[0].Imm)
	}
	return Instr{Op: op, Args: args, Raw: raw}, index, true, nil
}
