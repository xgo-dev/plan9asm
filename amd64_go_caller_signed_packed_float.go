package plan9asm

func x86CallerSignedPackedFloatStep(ins *Instr, f x86SignedPackedFloatForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	// Virtual MMX has no complete public caller x87/tag/physical alias contract.
	if f.mmx || f.mask >= 0 && !state.masks[ins.Args[f.mask].Reg] {
		return false
	}
	if f.memory >= 0 {
		source := ins.Args[f.memory]
		if source.Kind == OpFP || source.Kind == OpMem &&
			(source.Mem.Base == SP || source.Mem.Base == BP || source.Mem.Index == BP) {
			return false
		}
		// The full potential tuple, even for inactive masks, is read-only input.
		// The actual native opcode retains lane fault suppression; initialized
		// masks do not authorize missing bytes or writable input pointers.
		if !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.memoryBytes), false) {
			return false
		}
	} else {
		input := state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)]
		mask := x86CallerVectorByteMask(int64(f.inputBytes))
		if input&mask != mask {
			return false
		}
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	width := x86CallerVectorByteMask(int64(f.byteWidth))
	old := state.vectors[destination]
	if f.mask >= 0 && !f.zeroing && old&width != width {
		return false
	}
	if f.spec.legacy {
		state.vectors[destination] = old&^width | width
	} else {
		state.vectors[destination] = ^uint64(0)
	}
	return true
}
