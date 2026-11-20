package plan9asm

func x86CallerDwordProductStep(ins *Instr, form x86DwordProductForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	first := state.vectors[x86CallerVectorRoot(form.source.Reg)] & width
	if form.memory >= 0 {
		// Even dwords are the numerical inputs, but the possible native read
		// remains m128/m256/m512 or m64bcst, independent of the mask value.
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = width
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)] & width
	var known uint64
	for start := 0; start < form.byteWidth; start += 8 {
		input := uint64(15) << uint(start)
		output := uint64(255) << uint(start)
		if first&input == input && second&input == input {
			known |= output
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	if form.mask >= 0 && !form.zeroing {
		known &= old
	}
	if form.legacy {
		state.vectors[destination] = old&^width | known
	} else {
		state.vectors[destination] = ^width | known
	}
	return true
}
