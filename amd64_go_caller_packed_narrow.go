package plan9asm

func x86CallerPackedNarrowStep(ins *Instr, form x86PackedNarrowForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	first := state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)] & width
	if form.memory >= 0 {
		// E4NF/.nb requires the complete tuple, even when every output mask
		// bit is zero. The form supplies a width, never a pointer permission.
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = width
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)] & width
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	known := x86PackedNarrowDefinedBytes(form, first, second, old)
	if form.legacy {
		state.vectors[destination] = old&^width | known
	} else {
		state.vectors[destination] = ^width | known
	}
	return true
}
