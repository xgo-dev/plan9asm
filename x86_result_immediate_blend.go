package plan9asm

// Byte selection does not initialize the unselected register bytes or create
// a pointer. Native memory still reads the complete tuple even at imm8=0.
func x86ResultImmediateBlendStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	f, known, err := x86ImmediateBlendProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(local) {
		if !native || !x86RawImmediateBlendSource(ins, arch) {
			return false, true
		}
		// Preserve the already validated physical form. Reparsing this
		// projection would incorrectly apply Go386's named operand limit.
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	var first uint64
	if f.memory {
		if !x86ResultReadWithNativeContinuation(local, ins.Args[f.source], int64(f.byteWidth), state, owned, arch, native) {
			return false, true
		}
		first = x86CallerVectorByteMask(int64(f.byteWidth))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[f.source].Reg, f.byteWidth)
		first = state.vectorBytes(index)
	}
	baseIndex, _ := amd64VectorRegisterIndex(ins.Args[f.base].Reg, f.byteWidth)
	base := state.vectorBytes(baseIndex)
	var defined uint64
	for output := 0; output < f.byteWidth; output++ {
		source := base
		if f.selectsFirst(output) {
			source = first
		}
		defined |= (source >> uint(output) & 1) << uint(output)
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	state.writeVector(destination, f.byteWidth, defined, f.legacy)
	return true, true
}

func x86RawImmediateBlendSource(ins Instr, arch string) bool {
	f, known, err := x86ImmediateBlendProperties(ins.Op, ins, arch)
	return known && err == nil && ins.x86Encoded != f.legacy &&
		x86RawOrdinaryVectorSourceAt(ins, arch, f.source)
}
