package plan9asm

func x86CallerSADStep(ins *Instr, form x86PackedSADForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	first := state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)] & width
	if form.memory >= 0 {
		// A selected dword or zero mask does not shrink the native access.
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = width
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)] & width
	var known uint64
	for output := 0; output < form.byteWidth; output += 2 {
		a, b := form.wordInputs(output)
		if first&a == a && second&b == b {
			known |= uint64(3) << uint(output)
		}
	}
	if form.constantZero(*ins) {
		known = width
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
