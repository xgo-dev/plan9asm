package plan9asm

// Memory availability is separate from the register's defined-byte transfer.
// conditionalRead is only supplied by the lowering-only, source-wide observer
// paired with an exact native aligned or unaligned volatile read. It is never a
// public observer, initialized-pointee, extent, alignment or write permission.
func x86ResultPackedVectorMoveTransfer(ins Instr, form amd64PackedVectorMoveForm, state *x86ResultState, owned []bool, resultOffset int64, arch string, conditionalRead bool) bool {
	if form.undefinedOpcode() {
		return false
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	width := int64(form.byteWidth)
	widthMask := x86CallerVectorByteMask(width)
	known := widthMask
	if form.memory >= 0 && form.spec.aligned && !form.ordinaryMemory(ins, arch) {
		// Virtual FP/AUTO storage is not the original aligned memory. Ordinary
		// memory instead retains its actual opcode: continuation defines its
		// active bytes without assuming that its native address was aligned.
		return false
	}
	if form.memory == 0 {
		if !conditionalRead && !x86ResultRead(ins.Args[0], width, state, owned, arch) {
			return false
		}
	} else {
		index, valid := amd64VectorRegisterIndex(ins.Args[0].Reg, form.byteWidth)
		if !valid {
			return false
		}
		known = state.vectorBytes(index) & widthMask
	}
	if form.memoryWrite {
		if known != widthMask {
			return false
		}
		destination := ins.Args[form.destination]
		if conditionalRead && form.ordinaryMemory(ins, arch) &&
			x86ResultIncomingPointerAddressIdentity(destination, state, arch) {
			// The paired native store does not read inactive destination lanes
			// and establishes no logical storage, bounds or future read facts.
			return true
		}
		if form.mask >= 0 && !x86ResultRead(destination, width, state, owned, arch) {
			return false // An unknown mask may retain any old destination byte.
		}
		return x86ResultStore(destination, width, state, owned, resultOffset, arch)
	}
	destination, valid := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if !valid {
		return false
	}
	known = form.definedActiveBytes(known, state.vectorBytes(destination))
	state.writeVector(destination, form.byteWidth, known, false)
	return true
}
