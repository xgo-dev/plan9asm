package plan9asm

// Packed bitwise operations do not write flags or GP/stack state. Their byte
// availability is independent of the shared operand grammar. MMX has no
// reviewed private caller move bank and must not be aliased to virtual Z0.
func x86CallerPackedLogicalStep(ins *Instr, form x86PackedLogicalForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	first := uint64(0)
	if form.memory >= 0 {
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = width
	} else {
		first = state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)] & width
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)] & width
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	known := x86PackedLogicalDefinedBytes(*ins, form, first, second, old)
	if form.legacy {
		state.vectors[destination] = old&^width | known
	} else {
		// Every VEX/EVEX width clears all higher physical register bits.
		state.vectors[destination] = ^width | known
	}
	return true
}
