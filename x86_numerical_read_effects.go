package plan9asm

// The actual SB source bytes are supplied only by a checked live certificate.
// All consumers use this same typed shape for the remaining numerical GP and
// flags effects; no observer turns the global into a pointer or numeric literal.
func x86NumericalReadEffect(ins Instr, arch string) (x86TypedByteEffect, bool) {
	_, form, valid := numericalCertifiedRead(ins, arch)
	if !valid {
		return x86TypedByteEffect{}, false
	}
	if form.spec.vector == x86NumericalSBAES {
		effect, known, err := x86TypedAESByteEffect(ins.Op, ins, arch)
		if !known || err != nil {
			return x86TypedByteEffect{}, false
		}
		return numericalVectorRegisterEffect(effect, form.operand), true
	}
	if form.spec.vector == x86NumericalSBLogical {
		logical, _, _ := x86PackedLogicalProperties(ins, arch)
		effect := x86TypedByteEffect{operands: []x86TypedByteOperand{
			{index: logical.second, operand: ins.Args[logical.second], width: int64(logical.byteWidth), read: true},
			{index: logical.destination, operand: ins.Args[logical.destination], width: int64(logical.byteWidth),
				read: logical.mask >= 0 && !logical.zeroing, write: true},
		}}
		return effect, true
	}
	partner := x86TypedByteOperand{index: form.partner, operand: ins.Args[form.partner], width: form.spec.gpBytes,
		read: form.spec.compare, write: !form.spec.compare}
	effect := x86TypedByteEffect{operands: []x86TypedByteOperand{partner}}
	if form.spec.compare {
		effect.flagsDefined, effect.flagsKilled = x86ByteFlagsAll, x86ByteFlagsAll
	}
	return effect, true
}

func numericalVectorRegisterEffect(effect x86TypedByteEffect, memory int) x86TypedByteEffect {
	registers := effect.operands[:0]
	for _, operand := range effect.operands {
		if operand.index != memory {
			registers = append(registers, operand)
		}
	}
	effect.operands = registers
	return effect
}

func x86ResultNumericalReadStep(ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) (bool, bool) {
	if ins.x86NumericalRead == nil {
		return false, false
	}
	if _, form, valid := numericalCertifiedRead(ins, arch); valid && form.spec.vector != x86NumericalSBScalar {
		return x86ResultNumericalVectorStep(ins, state, arch, form)
	}
	effect, valid := x86NumericalReadEffect(ins, arch)
	if !valid {
		return false, true
	}
	for _, operand := range effect.operands {
		if operand.read && !x86ResultRead(operand.operand, operand.width, state, owned, arch) ||
			operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, offset, arch) {
			return false, true
		}
	}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}

func x86CallerNumericalReadStep(ins Instr, state *x86SourceStackState) (bool, bool) {
	if ins.x86NumericalRead == nil {
		return false, false
	}
	if _, form, valid := numericalCertifiedRead(ins, "amd64"); valid && form.spec.vector != x86NumericalSBScalar {
		return numericalVectorMapStep(ins, "amd64", form, state.vectors, state.masks), true
	}
	effect, valid := x86NumericalReadEffect(ins, "amd64")
	if !valid {
		return false, true
	}
	for _, operand := range effect.operands {
		if operand.read && !x86CallerNumericRead(operand.operand, operand.width, state) ||
			operand.write && !x86CallerNumericWrite(operand.operand.Reg, operand.width, state) {
			return false, true
		}
	}
	if effect.flagsDefined != 0 {
		state.numericFlags = true
	}
	return true, true
}
