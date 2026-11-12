package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// Named forms retain Go's source operand grammar before sharing the physical
// decoder's numerical lowering. A WORD's decoder identity is not lent to them.
func parseARM64NamedMoveWide(op Op, ins Instr) (form arm64RawMoveWide, handled bool, err error) {
	switch op {
	case "MOVK", "MOVKW", "MOVN", "MOVNW", "MOVZ", "MOVZW":
	default:
		return form, false, nil
	}
	invalid := func() (arm64RawMoveWide, bool, error) {
		return form, true, fmt.Errorf("arm64 %s requires a nonzero shifted uint16 and C_ZREG: %q", op, ins.Raw)
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat ||
		ins.Args[0].Imm == 0 || !arm64ScalarMultiplyRegister(ins.Args[1]) {
		return invalid()
	}
	form.op, form.width = Op(strings.TrimSuffix(string(op), "W")), 64
	if strings.HasSuffix(string(op), "W") {
		form.width = 32
	}
	value := uint64(ins.Args[0].Imm)
	for shift := 0; shift < form.width; shift += 16 {
		if value&^(uint64(0xffff)<<shift) == 0 {
			form.shift, form.immediate = shift, uint16(value>>shift)
			form.destination = arm64NamedFieldRegister(ins.Args[1].Reg)
			return form, true, nil
		}
	}
	return invalid()
}

func parseARM64NamedBitfield(op Op, ins Instr) (form arm64RawBitfield, handled bool, err error) {
	switch op {
	case "BFM", "BFMW", "SBFM", "SBFMW", "UBFM", "UBFMW":
	default:
		return form, false, nil
	}
	invalid := func() (arm64RawBitfield, bool, error) {
		return form, true, fmt.Errorf("arm64 %s requires $immr, C_ZREG, $imms, C_ZREG: %q", op, ins.Raw)
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 ||
		!arm64ScalarMultiplyRegister(ins.Args[1]) || !arm64ScalarMultiplyRegister(ins.Args[3]) {
		return invalid()
	}
	form.op, form.width = Op(strings.TrimSuffix(string(op), "W")), 64
	if strings.HasSuffix(string(op), "W") {
		form.width = 32
	}
	for _, index := range []int{0, 2} {
		argument := ins.Args[index]
		if argument.Kind != OpImm || argument.ImmRaw != "" || argument.ImmIsFloat ||
			argument.Imm < 0 || argument.Imm >= int64(form.width) {
			return invalid()
		}
	}
	form.immr, form.imms = int(ins.Args[0].Imm), int(ins.Args[2].Imm)
	form.source, form.destination = arm64NamedFieldRegister(ins.Args[1].Reg), arm64NamedFieldRegister(ins.Args[3].Reg)
	return form, true, nil
}

// Call only after the complete C_ZREG check above; register 31 is ZR, not SP.
func arm64NamedFieldRegister(reg Reg) int {
	if reg == ZR {
		return 31
	}
	number, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(reg))), "R"))
	return number
}
