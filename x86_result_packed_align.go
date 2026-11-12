package plan9asm

// The result proof propagates selected-byte knowledge, never treats unknown
// register input as zero. Native accesses and masks remain mandatory even
// when the numerical result is dead or a large byte selector returns zero.
func x86ResultPackedAlignStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86PackedAlignProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	var first uint64
	if form.memory >= 0 {
		source := ins.Args[form.first]
		if form.legacy && source.Kind == OpFP ||
			!x86ResultReadWithNativeContinuation(ins, source, int64(form.memoryBytes), state, owned, arch, native) {
			return false, true
		}
		first = x86CallerVectorByteMask(int64(form.byteWidth))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.first].Reg, form.byteWidth)
		first = state.vectorBytes(index)
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	defined := form.definedBytes(first, state.vectorBytes(second), state.vectorBytes(destination))
	state.writeVector(destination, form.byteWidth, defined, form.legacy)
	return true, true
}

func x86CallerPackedAlignStep(ins *Instr, form x86PackedAlignForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	first := uint64(0)
	if form.memory >= 0 {
		// An ordinary caller slice supplies no legacy m128 alignment witness.
		if form.legacy || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = x86CallerVectorByteMask(int64(form.byteWidth))
	} else {
		first = state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)]
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	known := form.definedBytes(first, state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)], old)
	upper := ^x86CallerVectorByteMask(int64(form.byteWidth))
	if form.legacy {
		upper &= old
	}
	state.vectors[destination] = upper | known
	return true
}
