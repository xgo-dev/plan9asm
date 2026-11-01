package plan9asm

import (
	"fmt"
	"strings"
)

// The Go 1.27 table has one GFNI family: multiply (0F38 CF, W0) and the
// affine/inverse pair (0F3A CE/CF, W1). Its VEX rows are X/Y; EVEX adds Z,
// masks, zeroing and, only for the affine matrix source, qword broadcast.
func decodedX86GFNIInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok {
		return Instr{}, 0, false, nil
	}

	var op Op
	var immediate bool
	switch {
	case p.mapNumber == 2 && p.opcode == 0xcf:
		op = "VGF2P8MULB"
	case p.mapNumber == 3 && p.opcode == 0xce:
		op, immediate = "VGF2P8AFFINEQB", true
	case p.mapNumber == 3 && p.opcode == 0xcf:
		op, immediate = "VGF2P8AFFINEINVQB", true
	default:
		return Instr{}, 0, false, nil
	}
	if p.w != immediate {
		return Instr{}, 0, true, fmt.Errorf("%s has invalid W bit", op)
	}
	if p.broadcast && !immediate {
		return Instr{}, 0, true, fmt.Errorf("%s has no broadcast form", op)
	}

	laneBits := 8
	if immediate {
		laneBits = 64
	}
	instruction, length, _, err := decodedX86BinaryVectorOperands(code, p, mode, op, laneBits)
	if err != nil {
		return Instr{}, 0, true, err
	}
	if !immediate {
		return instruction, length, true, nil
	}
	if len(code) <= length {
		return Instr{}, 0, true, fmt.Errorf("%s is missing its imm8", op)
	}
	instruction.Args = append([]Operand{{Kind: OpImm, Imm: int64(code[length])}}, instruction.Args...)
	length++
	parts := make([]string, len(instruction.Args))
	for index, arg := range instruction.Args {
		parts[index] = arg.String()
	}
	instruction.Raw = fmt.Sprintf("%s %s", instruction.Op, strings.Join(parts, ", "))
	return instruction, length, true, nil
}
