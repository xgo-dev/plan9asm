package plan9asm

func x86CallerGPSIMDTransferStep(ins *Instr, f x86GPSIMDTransferForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if f.mmx || f.spec.rawOnly {
		return false
	}
	width := int64(f.bits / 8)
	lowMask := x86CallerVectorByteMask(width)
	var known uint64
	if f.sourceX {
		known = state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)] & lowMask
	} else if f.memory < 0 {
		root, valid := x86CallerGP(ins.Args[0].Reg)
		_, pointer := state.callers[root]
		if ins.Args[0].Kind != OpReg || !valid || root == SP || root == BP || pointer {
			return false
		}
		known = uint64(state.known[root]) & lowMask
	} else {
		known = lowMask
	}
	if !f.destinationX && known != lowMask {
		return false
	}
	if f.memory >= 0 && !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, width, f.memoryWrite) {
		return false
	}
	if f.destinationX {
		root := x86CallerVectorRoot(ins.Args[1].Reg)
		state.vectors[root] = f.definedVectorBytes(known, state.vectors[root])
		return true
	}
	if f.memoryWrite {
		return true
	}
	return x86CallerNumericWrite(ins.Args[1].Reg, width, state)
}
