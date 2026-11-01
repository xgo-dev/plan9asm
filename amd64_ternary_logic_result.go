package plan9asm

func x86ResultTernaryLogicStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultTernaryLogicContinuationStep(ins, state, owned, arch, false)
}

// Only the paired lowering observer may consume the exact E4 volatile reads.
// Boolean independence, zero masks and dead results supply no pointer or
// reusable backing. The standalone transfer retains its original boundary.
func x86ResultTernaryLogicContinuationStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, recognized, err := x86TernaryLogicProperties(ins.Op, ins, arch)
	if !recognized {
		return false, false
	}
	if err != nil {
		return false, true
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		literal := state.loweredStaticReads != nil && x86RawTernaryLogicLiteralForm(ins, arch)
		if !literal && (!nativeRead || !x86RawTernaryLogicSource(ins, arch)) {
			return false, true
		}
		// Capture the physical form above. A lowering-local numerical view
		// must not reapply the separate named386 arity limit afterward.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86ResultTernaryLogicInputs(ins, form, state, owned, arch, nativeRead), true
}

func x86ResultTernaryLogicInputs(ins Instr, form x86TernaryLogicForm, state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if form.mask >= 0 {
		index, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[index] {
			return false
		}
	}
	// Fault suppression and truth-table independence never grant authority to
	// read an unknown address or a partially described memory tuple.
	if form.memory >= 0 && !x86ResultReadWithNativeContinuation(ins, ins.Args[form.memory], int64(form.memoryBytes), state, owned, arch, nativeRead) {
		return false
	}
	known := x86CallerVectorByteMask(int64(form.byteWidth))
	dependencies := form.dependencies()
	if form.mask >= 0 && !form.zeroing {
		dependencies |= 1 // Inactive merging lanes preserve A.
	}
	for role, argument := range form.inputs {
		if dependencies>>uint(role)&1 == 0 || argument == form.memory {
			continue
		}
		index, _ := amd64VectorRegisterIndex(ins.Args[argument].Reg, form.byteWidth)
		known &= state.vectorBytes(index)
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth, known, false)
	return true
}
