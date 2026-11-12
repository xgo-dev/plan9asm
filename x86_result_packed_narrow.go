package plan9asm

// A partial numerical source defines only its independently computed output
// elements. Memory always retains the complete E4NF/.nb source tuple, even
// when a result is discarded or its output mask is zero.
func x86ResultPackedNarrowStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86PackedNarrowProperties(ins, arch)
	if !known || err != nil || form.mmx {
		return false, known // Physical MMX/x87 remains an independent entry role.
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false, true
		}
	}
	var first uint64
	if form.memory >= 0 {
		// Logical FP/AUTO bytes cannot prove native legacy m128 alignment.
		_, static := x86StaticSBReadAddress(form.source, arch)
		if form.legacy && !static && !nativeRead {
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
	defined := x86PackedNarrowDefinedBytes(form, first, state.vectorBytes(second), state.vectorBytes(destination))
	state.writeVector(destination, form.byteWidth, defined, form.legacy)
	return true, true // No FLAGS/DF, mask or memory facts change.
}
