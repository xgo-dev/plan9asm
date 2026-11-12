package plan9asm

func x86CallerPackedWrappingAddStep(ins *Instr, form x86PackedAddForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	return x86CallerPackedLaneArithmeticStep(ins, form.x86PackedBinaryForm, form.spec.laneBits, state, proof)
}

// Each complete input lane determines one output lane for wrapping or
// saturating integer add/subtract or low-product multiplication. Form sharing
// grants no address permission.
func x86CallerPackedLaneArithmeticStep(ins *Instr, form x86PackedBinaryForm, bits int, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	first := state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)] & width
	if form.memory >= 0 {
		// Source permission still requires the full original possible access
		// envelope; an initialized K mask does not prove a smaller region.
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		first = width
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)] & width
	var known uint64
	step := bits / 8
	for index := 0; index < form.byteWidth; index += step {
		lane := x86CallerVectorByteMask(int64(step)) << uint(index)
		if first&lane == lane && second&lane == lane {
			known |= lane
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
