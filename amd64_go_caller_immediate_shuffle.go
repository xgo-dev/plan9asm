package plan9asm

// Byte availability follows the exact immediate permutation. No unused byte,
// initialized mask, or shadow zero value establishes additional input data.
func x86CallerImmediateShuffleStep(ins *Instr, form x86ImmediateShuffleForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.spec.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	var source uint64
	if form.memory >= 0 {
		// Caller-region identity does not promise legacy m128 alignment.
		// E4NF memory keeps its full native tuple, including at mask zero.
		if form.spec.legacy || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		source = x86CallerVectorByteMask(int64(form.memoryBytes))
	} else {
		source = state.vectors[x86CallerVectorRoot(form.source.Reg)]
	}
	known := uint64(0)
	for byteIndex := 0; byteIndex < form.byteWidth; byteIndex++ {
		known |= (source >> uint(form.sourceByte(byteIndex)) & 1) << uint(byteIndex)
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	if form.mask >= 0 && !form.zeroing {
		known &= old // Unknown initialized K may retain any old lane.
	}
	if form.spec.legacy {
		state.vectors[destination] = old&^width | known
	} else {
		state.vectors[destination] = ^width | known
	}
	return true
}
