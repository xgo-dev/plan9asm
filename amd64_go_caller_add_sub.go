package plan9asm

func x86CallerFloatAddSubStep(ins *Instr, form x86FloatAddSubForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	return x86CallerFloatBinaryStep(ins, form.x86FloatBinaryForm, state, proof)
}

func x86CallerFloatBinaryStep(ins *Instr, form x86FloatBinaryForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := int64(form.byteWidth)
	if form.scalar {
		width = int64(form.bits / 8)
	}
	required := x86CallerVectorByteMask(width)
	if form.memory >= 0 && !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
		return false
	}
	for _, index := range []int{form.first, form.second} {
		if form.literal && index == form.first {
			continue
		}
		if index != form.memory && state.vectors[x86CallerVectorRoot(ins.Args[index].Reg)]&required != required {
			return false
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	// A merely initialized mask does not prove any lane active. Merge needs
	// the old numerical lane(s), zeroing does not; neither invents inputs.
	if form.mask >= 0 && !form.zeroing && old&required != required {
		return false
	}
	known := ^uint64(0)
	if form.legacy {
		known = old | required
	} else if form.scalar {
		upperX := x86CallerVectorByteMask(16) &^ required
		second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)]
		known = ^x86CallerVectorByteMask(16) | required | second&upperX
	}
	state.vectors[destination] = known
	return true
}
