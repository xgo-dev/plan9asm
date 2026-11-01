package plan9asm

// Legacy/VEX comparisons write vector lanes; EVEX comparisons write K bits.
// Their common operand grammar must not erase these different destination
// roles. Complete numerical inputs confer no native/caller memory permission.
func x86ResultVectorCompareStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultVectorCompareStepWithRead(ins, state, owned, arch, false)
}

func x86ResultVectorCompareStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch)
	namedIntegerCompare := known
	if !known {
		immediate, recognized, immediateErr := x86ImmediatePackedCompareProperties(ins.Op, ins, arch)
		form, known, err = immediate.x86PackedIntegerCompareForm, recognized, immediateErr
	}
	if !known {
		return false, false
	}
	if err != nil || form.mmx {
		return false, true
	}
	// Only the named lowering continuation may project complete result lanes.
	// Raw encodings call the strict transfer below, even after their local
	// provenance handoff; standalone queries and K results remain all-input.
	if nativeRead && namedIntegerCompare && !form.maskResult && form.mask < 0 && x86ResultNamedPredicateInstruction(ins) {
		return x86ResultNamedCompareLaneTransfer(ins, form, state, owned, arch)
	}
	return x86ResultVectorCompareTransfer(ins, form, state, owned, arch, nativeRead)
}

func x86ResultNamedCompareLaneTransfer(ins Instr, form x86PackedIntegerCompareForm,
	state *x86ResultState, owned []bool, arch string) (bool, bool) {
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	defined := required
	if !form.identicalVectorInputs(ins) {
		for _, input := range []int{form.first, form.second} {
			operand := ins.Args[input]
			if input == form.first {
				operand = form.source
			}
			if input == form.memory {
				// Partial result knowledge never reduces the original memory
				// access, including its extent and actual address obligations.
				if !x86ResultReadWithNativeContinuation(ins, operand, int64(form.memoryBytes), state, owned, arch, true) {
					return false, true
				}
				continue
			}
			index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
			if !valid {
				return false, true
			}
			defined &= state.vectorBytes(index)
		}
	}
	// Integer EQ/GT depends on every bit of its own lane, not other lanes.
	// One unknown byte therefore invalidates that entire result lane only.
	laneBytes := form.spec.laneBits / 8
	for offset := 0; offset < form.byteWidth; offset += laneBytes {
		lane := x86CallerVectorByteMask(int64(laneBytes)) << uint(offset)
		if defined&lane != lane {
			defined &^= lane
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth, defined, form.legacy)
	return true, true
}

// A validated physical form survives the lowering-local provenance handoff.
// Do not reparse it under named mode32 operand limits after that handoff.
func x86ResultVectorCompareTransfer(ins Instr, form x86PackedIntegerCompareForm, state *x86ResultState,
	owned []bool, arch string, nativeRead bool) (bool, bool) {
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false, true
		}
	}
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	for _, input := range []int{form.first, form.second} {
		if form.identicalVectorInputs(ins) {
			break // Same-view integer identities need no incoming numerical bytes.
		}
		operand := ins.Args[input]
		if input == form.first {
			operand = form.source
		}
		if input == form.memory {
			if !x86ResultReadWithNativeContinuation(ins, operand, int64(form.memoryBytes), state, owned, arch, nativeRead) {
				return false, true
			}
			continue
		}
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		if !valid || state.vectorBytes(index)&required != required {
			return false, true
		}
	}
	destination := ins.Args[form.destination].Reg
	if form.maskResult {
		index, _ := amd64ParseKReg(destination)
		state.masks[index] = true
	} else {
		index, _ := amd64VectorRegisterIndex(destination, form.byteWidth)
		state.writeVector(index, form.byteWidth, required, form.legacy)
	}
	return true, true
}
