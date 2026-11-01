package plan9asm

// The paired native comparison keeps the full immediate, MXCSR, mask and
// fault behavior. Its continued execution defines numerical result bytes;
// it supplies no caller/frame backing, pointer extent or raw-entry authority.
func x86ResultFloatCompareStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86FloatCompareProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) && !x86RawFloatCompareLiteralForm(ins, arch) {
		if !nativeRead || !x86RawLegacyFloatCompareSource(ins, arch) {
			return false, true
		}
		// Only this paired numerical transfer consumes a named local view.
		// The emitter and immutable replay retain every original selector and
		// operand, and neither raw entry nor independent DATA authority follows.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	if form.mask >= 0 {
		mask, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[mask] {
			return false, true
		}
	}
	required := x86CallerVectorByteMask(int64(form.inputByteWidth()))
	for _, ordinal := range []int{form.first, form.second} {
		operand := ins.Args[ordinal]
		if ordinal == form.memory {
			if operand.Kind == OpFP && !form.scalar ||
				!x86ResultReadWithNativeContinuation(ins, operand, int64(form.memoryBytes), state, owned, arch, nativeRead) {
				return false, true
			}
			continue
		}
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		if !valid || state.vectorBytes(index)&required != required {
			return false, true
		}
	}
	if form.maskResult {
		index, valid := amd64ParseKReg(ins.Args[form.destination].Reg)
		if !valid {
			return false, true
		}
		state.masks[index] = true
		return true, true // A K destination is not an old merge input.
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	defined := form.resultDefinedBytes(state.vectorBytes(second), state.vectorBytes(destination))
	state.writeVector(destination, form.byteWidth, defined, form.legacy)
	return true, true // Arithmetic FLAGS/DF are preserved; MXCSR stays native.
}
