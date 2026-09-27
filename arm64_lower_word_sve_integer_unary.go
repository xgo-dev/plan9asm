package plan9asm

import "fmt"

func decodeARM64RawSVEIntegerUnary(word uint32) (Instr, bool) {
	for op, spec := range arm64SVEIntegerUnarySpecs {
		variableFields := uint32(0x00c01fff) // size, Pg, Zn, Zd
		if spec.unpred {
			variableFields = 0x00c003ff // size, Zn, Zd
		}
		base, mode := word&^variableFields, "M"
		if base != spec.rawMerge {
			if spec.rawZero == 0 || base != spec.rawZero {
				continue
			}
			mode = "Z"
		}
		bits := 8 << (word >> 22 & 3)
		if bits < spec.minBits || spec.maxBits != 0 && bits > spec.maxBits {
			return Instr{}, false
		}
		width := "BHSD"[word>>22&3]
		args := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))}}
		if !spec.unpred {
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", word>>10&7, mode))})
		}
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))})
		return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}
