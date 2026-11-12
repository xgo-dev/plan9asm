package plan9asm

// This numerical observer shares the complete W/D/Q operand grammars. It
// supplies no caller region, native backing, pointer or raw-return permission.
func x86ResultPackedLowMultiplyStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	low, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, arch)
	form, bits := low.x86PackedBinaryForm, low.spec.laneBits
	if !known {
		word, wordKnown, wordErr := x86PackedWordMultiplyProperties(ins.Op, ins, arch)
		if !wordKnown || word.spec.mode != amd64PackedWordMultiplyLow {
			return false, false
		}
		form, bits, err = word.x86PackedBinaryForm, 16, wordErr
	}
	if err != nil || form.mmx {
		return false, true
	}
	return x86ResultPackedLaneArithmeticStep(ins, form, bits, state, owned, arch), true
}

// A lane is numerical only when every byte of both input lanes is known.
// This dependency rule is shared by low products and wrapping/saturating
// arithmetic, not their operations or their independent memory permissions.
func x86ResultPackedLaneArithmeticStep(ins Instr, form x86PackedBinaryForm, bits int, state *x86ResultState, owned []bool, arch string) bool {
	return x86ResultPackedLaneArithmeticStepWithRead(ins, form, bits, state, owned, arch, false)
}

func x86ResultPackedLaneArithmeticStepWithRead(ins Instr, form x86PackedBinaryForm, bits int,
	state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	if form.memory >= 0 {
		memory := ins.Args[form.memory]
		// Logical FP/AUTO bytes can establish numerical dependence, not the
		// original native alignment. Legacy lowering checks that separately.
		if !x86ResultReadWithNativeContinuation(ins, memory, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false
		}
	}
	bytes := func(index int) uint64 {
		if index == form.memory {
			return x86CallerVectorByteMask(int64(form.byteWidth))
		}
		register, _ := amd64VectorRegisterIndex(ins.Args[index].Reg, form.byteWidth)
		return state.vectorBytes(register)
	}
	first, second := bytes(form.first), bytes(form.second)
	var initialized uint64
	laneBytes := bits / 8
	for index := 0; index < form.byteWidth; index += laneBytes {
		lane := x86CallerVectorByteMask(int64(laneBytes)) << uint(index)
		if first&lane == lane && second&lane == lane {
			initialized |= lane
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if form.mask >= 0 && !form.zeroing {
		initialized &= state.vectorBytes(destination)
	}
	state.writeVector(destination, form.byteWidth, initialized, form.legacy)
	return true
}
