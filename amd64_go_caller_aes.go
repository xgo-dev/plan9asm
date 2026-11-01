package plan9asm

func x86CallerAESByteStep(ins *Instr, f x86AESForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	width := x86CallerVectorByteMask(int64(f.byteWidth))
	source := state.vectors[x86CallerVectorRoot(ins.Args[f.source].Reg)] & width
	if f.memory >= 0 {
		if !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.byteWidth), false) {
			return false
		}
		source = width
	}
	input := uint64(0)
	if f.state >= 0 {
		input = state.vectors[x86CallerVectorRoot(ins.Args[f.state].Reg)] & width
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	defined := x86AESDefinedBytes(f, source, input)
	if !f.spec.vector {
		state.vectors[destination] = state.vectors[destination]&^width | defined
	} else {
		state.vectors[destination] = ^width | defined
	}
	return true
}
