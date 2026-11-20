package plan9asm

// SAD shares its ordered byte selectors with the caller model and lowerer.
// Only selected register bytes contribute, but every memory form still reads
// its complete native tuple, including a zero mask or unused result.
func x86ResultSADStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86PackedSADProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if form.constantZero(ins) {
		state.writeVector(destination, form.byteWidth, width, form.legacy)
		return true, true
	}
	var requiredFirst, requiredSecond uint64
	for output := 0; output < form.byteWidth; output += 2 {
		first, second := form.wordInputs(output)
		requiredFirst |= first
		requiredSecond |= second
	}
	first := ins.Args[form.first]
	if form.memory >= 0 {
		// The legacy m128 opcode keeps its alignment and fault behavior.
		// Logical FP/AUTO bytes alone cannot establish that native storage.
		if _, static := x86StaticSBReadAddress(first, arch); form.legacy && !static &&
			(!nativeRead || !x86OrdinaryNativeMemoryOperand(first, arch)) {
			return false, true
		}
		if !x86ResultReadWithNativeContinuation(ins, first, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false, true
		}
	} else {
		index, _ := amd64VectorRegisterIndex(first.Reg, form.byteWidth)
		if state.vectorBytes(index)&requiredFirst != requiredFirst {
			return false, true
		}
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	if state.vectorBytes(second)&requiredSecond != requiredSecond ||
		form.mask >= 0 && !form.zeroing && state.vectorBytes(destination)&width != width {
		return false, true
	}
	state.writeVector(destination, form.byteWidth, width, form.legacy)
	return true, true // No GP, FLAGS, mask, DF, pointer or storage writes.
}
