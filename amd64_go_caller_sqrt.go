package plan9asm

func x86CallerSqrtStep(ins *Instr, f x86FloatBinaryForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if f.bits == 16 {
		return false // Raw FP16 retains its separate original-source continuation.
	}
	if f.mask >= 0 && !state.masks[ins.Args[f.mask].Reg] {
		return false
	}
	input := state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)]
	if f.memory >= 0 {
		// Ordinary caller bounds do not establish legacy m128 alignment.
		if f.legacy && !f.scalar || !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.memoryBytes), false) {
			return false
		}
		input = ^uint64(0)
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	upper := state.vectors[x86CallerVectorRoot(ins.Args[f.second].Reg)]
	value, valid := x86SqrtDefinedBytes(f, input, upper, state.vectors[destination])
	if !valid {
		return false
	}
	state.vectors[destination] = value
	return true
}
