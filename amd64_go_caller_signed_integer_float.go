package plan9asm

func x86CallerSignedIntegerFloatStep(ins *Instr, f x86SignedIntegerFloatForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if f.memory >= 0 {
		if !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.sourceBits/8), false) {
			return false
		}
	} else if !x86CallerNumericRead(ins.Args[0], int64(f.sourceBits/8), state) {
		return false
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	low := x86CallerVectorByteMask(int64(f.spec.resultBits / 8))
	if f.spec.legacy {
		state.vectors[destination] |= low
	} else {
		upper := state.vectors[x86CallerVectorRoot(ins.Args[f.upper].Reg)]
		state.vectors[destination] = ^x86CallerVectorByteMask(16) | low | upper&(x86CallerVectorByteMask(16)&^low)
	}
	return true
}
