package plan9asm

import "strings"

// Only descriptors with explicit vector storage/alias metadata participate.
func fixedLocalVectorByteEffect(ins Instr) (x86TypedByteEffect, bool, error) {
	if ins.x86NumericalRead != nil {
		return x86TypedByteEffect{}, false, nil // Preserve the existing owner-specific consumer.
	}
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	var effect x86TypedByteEffect
	var known bool
	var err error
	if strings.HasPrefix(base, "V") {
		effect, known, err = x86VectorDependencyByteEffect(ins.Op, ins, "amd64")
	} else {
		effect, known, err = x86PackedBinaryByteEffect(ins.Op, ins, "amd64")
	}
	if !known {
		effect, known, err = x86TypedPackedSADByteEffect(ins, "amd64")
	}
	for _, project := range [...]func(Op, Instr, string) (x86TypedByteEffect, bool, error){
		x86TypedPackedIntegerCompareByteEffect,
		x86TypedPackedAbsSignByteEffect,
		x86TypedPackedFloatShuffleByteEffect,
		x86TypedTernaryLogicByteEffect,
		x86TypedPackedDotByteEffect,
		x86TypedFourSourceByteEffect,
		x86TypedCOMIByteEffect,
		x86TypedScalarPrecisionByteEffect,
		x86TypedPackedPrecisionByteEffect,
		x86TypedNamedHalfByteEffect,
		x86TypedMoveHalfByteEffect,
		x86TypedDuplicateMoveByteEffect,
	} {
		if known {
			break
		}
		effect, known, err = project(ins.Op, ins, "amd64")
	}
	if !known {
		// These forms also accept individually typed scalar FP fields.
		return x86TypedFloatingHelperByteEffect(ins.Op, ins, "amd64")
	}
	if err != nil {
		return x86TypedByteEffect{}, true, goAMD64FrameContext("fixed local vector form is not closed: %v", err)
	}
	upper := effect.vector.upperWrite
	valid := upper == x86TypedVectorUpperPreserve && (effect.vector.memoryAlignment == 1 || effect.vector.memoryAlignment == 16) ||
		(upper == x86TypedVectorUpperZero || upper == x86TypedVectorNoWrite) && effect.vector.memoryAlignment == 1
	for _, operand := range effect.operands {
		switch operand.operand.Kind {
		case OpReg:
			if amd64IsKOperand(operand.operand) {
				valid = valid && operand.width == 8 && (operand.read || operand.write) &&
					(!operand.write || upper == x86TypedVectorNoWrite)
				continue
			}
			if operand.numericalGP {
				_, gp := x86CallerGP(operand.operand.Reg)
				valid = valid && gp && operand.read && !operand.write &&
					x86CallerByteMask(operand.operand.Reg, operand.width) != 0
				continue
			}
			width := amd64VectorByteWidth(operand.operand.Reg)
			index, vector := amd64VectorRegisterIndex(operand.operand.Reg, width)
			// A widening source can consume only the low bytes of its
			// physical register. A write still describes the whole view.
			valid = valid && vector && (index < 16 || upper != x86TypedVectorUpperPreserve) &&
				operand.width > 0 && operand.width <= int64(width) &&
				(!operand.write || operand.width == int64(width) && upper != x86TypedVectorNoWrite)
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
