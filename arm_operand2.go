package plan9asm

import (
	"math/bits"
	"strconv"
)

// A decoded immediate retains whether the physical rotation was zero.
// The same literal can have encodings with different carry out.
type armOperand2Encoding uint8

const (
	armNamedOperand2 armOperand2Encoding = iota
	armShiftedOperand2
	armUnrotatedOperand2
	armRotatedOperand2
)

// The 16 ordinary A32 data-processing slots (asm5's oprrr). Compare/test
// requires S=1 and Rd=0. Its S=0 space includes miscellaneous instructions,
// and the register-shift overlap includes multiply and extra loads/stores.
var armOperand2Opcodes = [...]Op{
	"AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC",
	"TST", "TEQ", "CMP", "CMN", "ORR", "MOVW", "BIC", "MVN",
}

func decodeARMRawOperand2(ins Instr) (Instr, bool) {
	if ins.Op != OpWORD || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm ||
		ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return Instr{}, false
	}
	word := uint32(ins.Args[0].Imm)
	if word&(3<<26) != 0 {
		return Instr{}, false
	}
	condition, valid := armRawCondition(word >> 28)
	if !valid {
		return Instr{}, false
	}
	opcode := word >> 21 & 15
	op := armOperand2Opcodes[opcode]
	setsFlags := word&(1<<20) != 0
	test := opcode >= 8 && opcode <= 11
	unary := op == "MOVW" || op == "MVN"
	rn, rd := word>>16&15, word>>12&15
	if test && (!setsFlags || rd != 0) || unary && rn != 0 {
		return Instr{}, false
	}
	// PC operands belong to the source-layout/control-flow rules.
	if rn == 15 || rd == 15 {
		return Instr{}, false
	}

	var source Operand
	encoding := armShiftedOperand2
	field := word & 0xfff
	if word&(1<<25) != 0 {
		rotation := int(field>>8) * 2
		source = Operand{Kind: OpImm, Imm: int64(bits.RotateLeft32(field&0xff, -rotation))}
		encoding = armUnrotatedOperand2
		if rotation != 0 {
			encoding = armRotatedOperand2
		}
	} else {
		rm := field & 15
		if field&0x90 == 0x90 || rm == 15 {
			return Instr{}, false
		}
		shifts := [...]ShiftOp{ShiftLeft, ShiftRight, ShiftArith, ShiftRotate}
		source = Operand{Kind: OpRegShift, Reg: armOperand2Reg(rm), ShiftOp: shifts[field>>5&3]}
		if field&(1<<4) == 0 {
			source.ShiftAmount = int64(field >> 7)
		} else {
			rs := field >> 8
			if rs == 15 {
				return Instr{}, false
			}
			source.ShiftReg = armOperand2Reg(rs)
		}
	}

	args := []Operand{source}
	if !unary {
		args = append(args, Operand{Kind: OpReg, Reg: armOperand2Reg(rn)})
	}
	if !test {
		args = append(args, Operand{Kind: OpReg, Reg: armOperand2Reg(rd)})
	}
	if condition != "AL" {
		op += Op("." + condition)
	}
	if setsFlags && !test {
		op += ".S"
	}
	return Instr{Op: op, Args: args, Raw: ins.Raw, armOperand2: encoding}, true
}

func armOperand2Reg(number uint32) Reg {
	return Reg("R" + strconv.Itoa(int(number)))
}

func (encoding armOperand2Encoding) readsCarry(source Operand) bool {
	return encoding == armShiftedOperand2 && source.Kind == OpRegShift &&
		source.ShiftOp == ShiftRotate && source.ShiftReg == "" && source.ShiftAmount == 0
}

func (encoding armOperand2Encoding) definesCarry(source Operand) bool {
	switch encoding {
	case armRotatedOperand2:
		return true
	case armShiftedOperand2:
		return source.ShiftReg == "" && (source.ShiftOp != ShiftLeft || source.ShiftAmount != 0)
	}
	return false
}

func (encoding armOperand2Encoding) immediateCarry(op string, source Operand) string {
	switch encoding {
	case armNamedOperand2:
		return armLogicalImmediateCarry(op, source)
	case armRotatedOperand2:
		return strconv.FormatBool(uint32(source.Imm)>>31 != 0)
	}
	return ""
}
