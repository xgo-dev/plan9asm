package plan9asm

func x86RawQwordLookupSource(ins Instr, arch string) bool {
	_, known, err := x86QwordLookupProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86ResultQwordLookupStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86QwordLookupProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawOrdinaryVectorSource(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	first := ins.Args[form.first]
	if form.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, first, int64(form.memoryBytes), state, owned, arch, native) {
			return false, true
		}
	} else if !x86ResultPackedVectorRead(first, int64(form.byteWidth), state, owned, arch) {
		return false, true
	}
	if !x86ResultPackedVectorRead(ins.Args[form.second], int64(form.byteWidth), state, owned, arch) {
		return false, true
	}
	if form.spec.output == amd64QwordBitLookupMask {
		destination, _ := amd64ParseKReg(ins.Args[form.destination].Reg)
		state.masks[destination] = true
	} else {
		if form.mask >= 0 && !form.zeroing &&
			!x86ResultPackedVectorRead(ins.Args[form.destination], int64(form.byteWidth), state, owned, arch) {
			return false, true
		}
		destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
		state.writeVector(destination, form.byteWidth, x86CallerVectorByteMask(int64(form.byteWidth)), false)
	}
	return true, true // No FLAGS, pointer, backing or reusable memory fact follows.
}
