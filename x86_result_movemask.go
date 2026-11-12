package plan9asm

// Every output bit depends only on its source sign byte; high bits are zero.
// Whole numerical GP bytes and one adjacent bit observation remain distinct.
// FLAGS/vector aliases, physical MMX and raw/mode32 source roles are unchanged.
func x86ResultMoveMaskStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86MoveMaskProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil || form.byteWidth == 8 {
		return false, true
	}
	index, valid := amd64VectorRegisterIndex(ins.Args[0].Reg, form.byteWidth)
	if !valid || arch == "386" && index >= 8 {
		return false, true
	}
	source := state.vectorBytes(index)
	named := x86ResultNamedPredicateInstruction(ins)
	if !named && source&x86CallerVectorByteMask(int64(form.byteWidth)) != x86CallerVectorByteMask(int64(form.byteWidth)) {
		return false, true // Partial named facts cannot establish a raw source role.
	}
	destination, _, valid := x86ResultGP(ins.Args[1].Reg, 4, arch)
	if !valid {
		return false, true
	}
	laneBytes := 1
	if form.floatingLaneBits != 0 {
		laneBytes = form.floatingLaneBits / 8
	}
	bits := ^uint64(0)
	for lane := 0; lane < form.byteWidth/laneBytes; lane++ {
		if source&(uint64(1)<<uint(lane*laneBytes+laneBytes-1)) == 0 {
			bits &^= uint64(1) << uint(lane)
		}
	}
	var bytes uint8
	for at := 0; at < 8; at++ {
		if byte(bits>>uint(8*at)) == 255 {
			bytes |= 1 << uint(at)
		}
	}
	if !x86ResultStore(ins.Args[1], 4, state, owned, resultOffset, arch) {
		return false, true
	}
	state.gp[destination] = bytes
	if named && bits != ^uint64(0) {
		state.gpBits = x86ResultGPBits{bits: bits, register: destination, valid: true}
	}
	return true, true
}
