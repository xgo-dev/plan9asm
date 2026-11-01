package plan9asm

func x86ResultImmediateShuffleStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultImmediateShuffleStepWithRead(ins, state, owned, arch, false)
}

func x86ResultImmediateShuffleStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86ImmediateShuffleProperties(ins, arch)
	if !known || err != nil || form.spec.mmx {
		return false, known // Physical MMX does not alias the SIMD result bank.
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false, true
		}
	}
	var source uint64
	if form.memory >= 0 {
		// A selected byte or zero mask cannot shrink the native memory tuple.
		// Legacy m128 also needs native alignment/backing; a logical FP/AUTO
		// allocation is not that witness. The paired original legacy opcode
		// retains alignment faults; continued execution asserts no alignment.
		if _, static := x86StaticSBReadAddress(form.source, arch); form.spec.legacy && !static &&
			(!nativeRead || !x86OrdinaryNativeMemoryOperand(form.source, arch)) {
			return false, true
		}
		if !x86ResultReadWithNativeContinuation(ins, form.source, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false, true
		}
		source = x86CallerVectorByteMask(int64(form.memoryBytes))
	} else {
		index, _ := amd64VectorRegisterIndex(form.source.Reg, form.byteWidth)
		source = state.vectorBytes(index)
	}
	var defined uint64
	for output := 0; output < form.byteWidth; output++ {
		defined |= (source >> uint(form.sourceByte(output)) & 1) << uint(output)
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if form.mask >= 0 && !form.zeroing {
		defined &= state.vectorBytes(destination)
	}
	state.writeVector(destination, form.byteWidth, defined, form.spec.legacy)
	return true, true
}
