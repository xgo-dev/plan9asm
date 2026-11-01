package plan9asm

// Numerical byte dependencies do not authenticate raw origin or native
// storage. Only the lowering continuation can consume the exact paired read.
func x86ResultBlendMinposStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86BlendMinposProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(local) {
		if !native || !x86RawBlendMinposSource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	var source uint64
	if form.memory {
		if !x86ResultReadWithNativeContinuation(local, ins.Args[form.source], int64(form.byteWidth), state, owned, arch, native) {
			return false, true
		}
		source = x86CallerVectorByteMask(int64(form.byteWidth))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.source].Reg, form.byteWidth)
		source = state.vectorBytes(index)
	}
	var initialized uint64
	if form.minimum {
		initialized = 0xfff8 // The instruction clears bits 127:19, independently of its input values.
		if source&0xffff == 0xffff {
			initialized |= 7
		}
	} else {
		maskIndex, _ := amd64VectorRegisterIndex(ins.Args[form.mask].Reg, form.byteWidth)
		baseIndex, _ := amd64VectorRegisterIndex(ins.Args[form.base].Reg, form.byteWidth)
		mask, base := state.vectorBytes(maskIndex), state.vectorBytes(baseIndex)
		laneBytes := form.laneBits / 8
		for at := 0; at < form.byteWidth; at++ {
			flag := uint((at/laneBytes+1)*laneBytes - 1)
			bit := uint64(1) << uint(at)
			if mask&(uint64(1)<<flag) != 0 && source&bit != 0 && base&bit != 0 {
				initialized |= bit
			}
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth, initialized, form.legacy)
	return true, true
}

func x86RawBlendMinposSource(ins Instr, arch string) bool {
	form, known, err := x86BlendMinposProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSourceAt(ins, arch, form.source)
}
