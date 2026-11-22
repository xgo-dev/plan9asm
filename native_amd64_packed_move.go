package plan9asm

import (
	"fmt"
	"strings"
)

// A physical move retains the original address, mask and instruction.
// The assembler checks syntax without inventing any alignment guarantee.
func (e *nativeAMD64) emitPackedMove(out *strings.Builder, ins Instr, name string, width, mask int, zeroing bool) error {
	var operands [2]string
	for i, index := range [2]int{0, len(ins.Args) - 1} {
		operand := ins.Args[index]
		if operand.Kind == OpReg {
			operands[i] = nativeAMD64VectorReg(operand.Reg, width)
			continue
		}
		address, err := e.operand(operand, 64)
		if err != nil {
			return err
		}
		operands[i] = address
	}
	dst := nativeAMD64DecorateMask(operands[1], ins, mask, zeroing)
	fmt.Fprintf(out, "\t%s %s, %s\n", name, operands[0], dst)
	return nil
}

// Its callers use a typed form that has already checked the register bank.
func nativeAMD64VectorReg(reg Reg, width int) string {
	bank := "xmm"
	switch width {
	case 32:
		bank = "ymm"
	case 64:
		bank = "zmm"
	}
	index, _ := amd64VectorRegisterIndex(reg, width)
	return fmt.Sprintf("%%%s%d", bank, index)
}

func nativeAMD64DecorateMask(destination string, ins Instr, mask int, zeroing bool) string {
	if mask >= 0 {
		destination += " {%" + strings.ToLower(string(ins.Args[mask].Reg)) + "}"
	}
	if zeroing {
		destination += " {z}"
	}
	return destination
}
