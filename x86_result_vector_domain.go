package plan9asm

// A numerical byte is known independently of its value. This domain models
// every byte in each physical vector bank, not just an observed low-X result.
// It grants no memory extent, alignment, initialized pointee or ABI permission.
func (state *x86ResultState) vectorBytes(index int) uint64 {
	return uint64(state.xmm[index]) | state.vectorUpper[index]
}

// Typed forms choose the active width and legacy versus VEX/EVEX write rule.
// Legacy writes preserve inactive aliases; VEX/EVEX writes define them as zero.
// known contains only numerical dependencies; memory effects stay independent.
func (state *x86ResultState) writeVector(index, width int, known uint64, legacy bool) {
	mask := x86CallerVectorByteMask(int64(width))
	if legacy {
		known = known&mask | state.vectorBytes(index)&^mask
	} else {
		known = known&mask | ^mask
	}
	state.xmm[index] = uint16(known)
	state.vectorUpper[index] = known &^ 0xffff
}
