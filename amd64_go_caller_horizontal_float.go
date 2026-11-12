package plan9asm

func x86CallerHorizontalFloatStep(ins *Instr, form x86HorizontalFloatForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.memory >= 0 {
		// SSE3's legacy m128 requires alignment. A slice/nonalias witness
		// does not establish that; VEX forms allow unaligned memory.
		if !form.spec.vector || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.byteWidth), false) {
			return false
		}
	}
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	for _, index := range []int{form.first, form.second} {
		if index != form.memory && state.vectors[x86CallerVectorRoot(ins.Args[index].Reg)]&required != required {
			return false
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	known := ^uint64(0)
	if !form.spec.vector {
		known = state.vectors[destination] | required
	}
	state.vectors[destination] = known
	return true
}
