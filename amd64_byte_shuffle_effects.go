package plan9asm

func x86ResultByteShuffleStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultByteShuffleStepWithRead(ins, state, owned, arch, false)
}

func x86ResultByteShuffleStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86ByteShuffleProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false, true
		}
	}
	control := uint64(0)
	if form.memory >= 0 {
		// Only the paired emitter may observe continuation past its complete
		// native read. A mask cannot shrink E4NF, certify alignment or grant
		// backing; public/caller observers keep their separate storage rules.
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[form.memory], int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false, true
		}
		control = x86CallerVectorByteMask(int64(form.byteWidth))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.first].Reg, form.byteWidth)
		control = state.vectorBytes(index)
	}
	data, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	initialized := x86ByteShuffleDefinedBytes(form.byteWidth, control, state.vectorBytes(data))
	if form.mask >= 0 && !form.zeroing {
		initialized &= state.vectorBytes(destination)
	}
	state.writeVector(destination, form.byteWidth, initialized, form.legacy)
	return true, true
}

func x86CallerByteShuffleStep(ins *Instr, form x86PackedBinaryForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	control := uint64(0)
	if form.memory >= 0 {
		// A bounded slice is not a witness for legacy m128 alignment.
		// E4NF vector reads require the full tuple even with a zero mask.
		if form.legacy || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
		control = width
	} else {
		control = state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)]
	}
	data := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)]
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	known := x86ByteShuffleDefinedBytes(form.byteWidth, control, data)
	if form.mask >= 0 && !form.zeroing {
		known &= old
	}
	if form.legacy {
		state.vectors[destination] = old&^width | known
	} else {
		state.vectors[destination] = ^width | known
	}
	return true
}
