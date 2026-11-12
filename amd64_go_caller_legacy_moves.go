package plan9asm

// Only the whole-source caller proof consumes this transfer. The shared Go
// grammar supplies width/direction; neither recognition nor a numerical vector
// supplies pointer, backing, native alignment or allocation-extent authority.
func x86CallerLegacyPackedMoveStep(ins *Instr, form x86LegacyPackedMoveForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	const width = int64(16)
	mask := x86CallerVectorByteMask(width)
	var known uint64
	if form.memory >= 0 {
		// Preserve the existing packed-move boundary: ordinary numerical
		// SliceData is not proof of the aligned opcode's native address.
		if form.aligned {
			return false
		}
		if form.memoryWrite && state.vectors[x86CallerVectorRoot(form.source.Reg)]&mask != mask {
			return false
		}
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, width, form.memoryWrite) {
			return false
		}
		if form.memoryWrite {
			return true
		}
		known = mask
	} else {
		// Register copies propagate unknown source bytes without making
		// them numeric. A later observable consumer still needs its bytes.
		known = state.vectors[x86CallerVectorRoot(form.source.Reg)] & mask
	}
	destination := x86CallerVectorRoot(form.destination.Reg)
	state.vectors[destination] = state.vectors[destination]&^mask | known
	return true // Legacy writes preserve every upper Y/Z byte and all FLAGS.
}
