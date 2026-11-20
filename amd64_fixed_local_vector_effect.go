package plan9asm

import "strings"

// Only descriptors with explicit vector storage/alias metadata participate.
// MMX, unregistered upper writes and wider banks keep their separate owners.
func fixedLocalVectorByteEffect(ins Instr) (x86TypedByteEffect, bool, error) {
	if ins.x86NumericalRead != nil {
		return x86TypedByteEffect{}, false, nil // Preserve the existing owner-specific consumer.
	}
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	if _, known := amd64Reciprocal14Specs[Op(base)]; known {
		return x86TypedFloatingHelperByteEffect(ins.Op, ins, "amd64")
	}
	parse := x86PackedBinaryByteEffect
	if strings.HasPrefix(strings.ToUpper(string(ins.Op)), "V") {
		parse = x86UnmaskedVEXByteEffect
	}
	effect, known, err := parse(ins.Op, ins, "amd64")
	if !known {
		effect, known, err = x86TypedPackedIntegerCompareByteEffect(ins.Op, ins, "amd64")
	}
	if !known {
		return effect, false, nil
	}
	if err != nil {
		return x86TypedByteEffect{}, true, goAMD64FrameContext("fixed local vector form is not closed: %v", err)
	}
	valid := effect.vector.upperWrite == x86TypedVectorUpperPreserve && effect.vector.memoryAlignment == 16 ||
		effect.vector.upperWrite == x86TypedVectorUpperZero && effect.vector.memoryAlignment == 1
	for _, operand := range effect.operands {
		switch operand.operand.Kind {
		case OpReg:
			width := amd64VectorByteWidth(operand.operand.Reg)
			index, vector := amd64VectorRegisterIndex(operand.operand.Reg, width)
			valid = valid && vector && index < 16 && operand.width == int64(width)
		case OpMem, OpSym:
			valid = valid && operand.width > 0
		case OpImm:
			valid = valid && operand.read && !operand.write && fixedLocalNumericRead(operand.operand, operand.width, nil)
		default:
			valid = false
		}
	}
	if !valid {
		return x86TypedByteEffect{}, true, goAMD64FrameContext("fixed local vector effect has an unbound storage or alias role: %s", ins.Op)
	}
	return effect, true, nil
}
