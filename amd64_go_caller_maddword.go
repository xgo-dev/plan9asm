package plan9asm

func x86CallerWordMultiplyAddStep(ins *Instr, form x86PackedMultiplyAddForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	first := state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)] & width
	if form.memory >= 0 {
		// E4NF.nb retains the complete source read even for a zero mask. The
		// native legacy bridge consumes this same actual pointer and opcode;
		// the caller witness grants a read envelope, not alignment/no-fault.
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = width
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)] & width
	var known uint64
	groupBytes := form.spec.outputBits / 8
	for byteIndex := 0; byteIndex < form.byteWidth; byteIndex += groupBytes {
		pair := (uint64(1)<<uint(groupBytes) - 1) << uint(byteIndex)
		if first&pair == pair && second&pair == pair {
			known |= pair
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
