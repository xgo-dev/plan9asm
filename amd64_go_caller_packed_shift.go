package plan9asm

// Availability is separate from encoding. No count, mask, or zero-valued
// shadow register is evidence that an incoming vector contains numeric data.
func x86CallerPackedShiftStep(ins *Instr, form x86PackedShiftForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	if form.memory >= 0 {
		// Legacy XMM uniform count loads still need an independently bound
		// native-address/fault contract. A slice identity alone does not
		// establish it; the original opcode, not MOVDQA, governs faults.
		if form.legacy || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	data := width
	if form.data != form.memory {
		data = state.vectors[x86CallerVectorRoot(ins.Args[form.data].Reg)] & width
	}
	if data != width {
		return false
	}
	counts := ^uint64(0)
	if ins.Args[form.count].Kind != OpImm && form.count != form.memory {
		countWidth := int64(form.byteWidth)
		if form.countMode == x86PackedShiftUniform {
			countWidth = 8 // The native register's upper count qword is ignored.
		}
		needed := x86CallerVectorByteMask(countWidth)
		counts = state.vectors[x86CallerVectorRoot(ins.Args[form.count].Reg)]
		if counts&needed != needed {
			return false
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	// The caller-entry contract deliberately retains its complete input
	// requirements above. Sharing numerical dependencies does not relax them.
	known := x86PackedShiftDefinedBytes(form, data, counts, old)
	if form.legacy {
		state.vectors[destination] = old&^width | known
	} else {
		state.vectors[destination] = ^width | known
	}
	return true
}
