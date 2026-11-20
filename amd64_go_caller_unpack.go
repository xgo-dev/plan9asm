package plan9asm

func x86CallerPackedUnpackStep(ins *Instr, form x86PackedUnpackForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	first := uint64(0)
	if form.memory >= 0 {
		// Legacy m128 needs native alignment, not just a slice-data identity.
		// No initialized mask shrinks an E4NF read's complete native extent.
		if form.legacy || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = width
	} else {
		first = state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)] & width
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)] & width
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	known := x86PackedUnpackDefinedBytes(form, first, second, old)
	if form.legacy {
		state.vectors[destination] = old&^width | known
	} else {
		state.vectors[destination] = ^width | known
	}
	return true
}
