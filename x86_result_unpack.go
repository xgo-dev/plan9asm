package plan9asm

// Interleave follows only the selected numerical bytes, including sparse
// inputs whose unused bytes remain unknown. The complete native memory tuple
// must be proved independently, even with an initialized or zeroing mask.
func x86ResultPackedUnpackStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultPackedUnpackStepWithRead(ins, state, owned, arch, false)
}

func x86ResultPackedUnpackStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86PackedUnpackProperties(ins, arch)
	if !known || err != nil || form.mmx {
		return false, known // Physical MMX remains a separate state bank.
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false, true
		}
	}
	var first uint64
	if form.memory >= 0 {
		// Logical FP/AUTO bytes do not prove legacy m128's native alignment.
		// A paired emitted static read retains its existing independent role.
		if _, static := x86StaticSBReadAddress(form.source, arch); form.legacy && !static &&
			(!nativeRead || !x86OrdinaryNativeMemoryOperand(form.source, arch)) {
			return false, true
		}
		if !x86ResultReadWithNativeContinuation(ins, form.source, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false, true
		}
		first = x86CallerVectorByteMask(int64(form.byteWidth))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.first].Reg, form.byteWidth)
		first = state.vectorBytes(index)
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	defined := x86PackedUnpackDefinedBytes(form, first, state.vectorBytes(second), state.vectorBytes(destination))
	state.writeVector(destination, form.byteWidth, defined, form.legacy)
	return true, true
}
