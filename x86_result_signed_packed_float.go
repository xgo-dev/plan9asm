package plan9asm

// Native conversion, rounding and exception behavior belong to the existing
// original-opcode emitter. Numerical availability grants no MXCSR, alignment,
// pointee, caller or physical-entry fact. Standalone queries have no native read.
func x86ResultSignedPackedFloatStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86SignedPackedFloatProperties(ins, arch)
	if !known || err != nil || form.mmx || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false, true
		}
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		index, valid := amd64VectorRegisterIndex(source.Reg, form.sourceBytes)
		mask := x86CallerVectorByteMask(int64(form.inputBytes))
		if !valid || state.vectorBytes(index)&mask != mask {
			return false, true
		}
	} else if !x86ResultReadWithNativeContinuation(ins, source, int64(form.memoryBytes), state, owned, arch, nativeRead) {
		return false, true
	}
	destination, valid := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	output := x86CallerVectorByteMask(int64(form.byteWidth))
	if !valid || form.mask >= 0 && !form.zeroing && state.vectorBytes(destination)&output != output {
		return false, true
	}
	state.writeVector(destination, form.byteWidth, output, form.spec.legacy)
	return true, true // EFLAGS, DF, GP, logical memory and pointer identities stay unchanged.
}
