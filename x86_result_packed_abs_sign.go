package plan9asm

// ABS and SIGN are nontrapping integer operations: unknown dead register
// data may remain unknown. Native addresses and K inputs are still required,
// even for Void or an unused result; this grants no backing or entry facts.
func x86ResultPackedAbsSignStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86PackedAbsSignProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) && !x86RawPackedAbsLiteralForm(ins, arch) {
		return false, true
	}
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	var first uint64
	if form.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[form.first], int64(form.memoryBytes), state, owned, arch, native) {
			return false, true
		}
		first = x86CallerVectorByteMask(int64(form.byteWidth))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.first].Reg, form.byteWidth)
		first = state.vectorBytes(index)
	}
	second := ^uint64(0)
	if form.spec.sign {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
		second = state.vectorBytes(index)
	}
	var initialized uint64
	laneBytes := form.spec.laneBits / 8
	for at := 0; at < form.byteWidth; at += laneBytes {
		lane := x86CallerVectorByteMask(int64(laneBytes)) << uint(at)
		if first&lane == lane && second&lane == lane {
			initialized |= lane
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if form.mask >= 0 && !form.zeroing {
		initialized &= state.vectorBytes(destination)
	}
	state.writeVector(destination, form.byteWidth, initialized, form.legacy)
	return true, true
}
