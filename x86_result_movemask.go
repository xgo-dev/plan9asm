package plan9asm

// The whole input vector must have numerical bytes. The GP result is a
// write-only zero-extended r32; FLAGS and every vector alias are unchanged.
// MMX physical state and mode32 high banks have no producer in this domain.
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
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	if state.vectorBytes(index)&required != required {
		return false, true
	}
	return x86ResultStore(ins.Args[1], 4, state, owned, resultOffset, arch), true
}
