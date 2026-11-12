package plan9asm

// This transfer consumes existing typed arithmetic syntax solely for numeric
// byte definedness. Native reads, caller certificates, ISA, exceptions and
// MXCSR remain the lowerer's independent contracts. X/Y/Z views share complete
// physical-bank byte state, including legacy preservation and vector clearing.
func x86ScalarFPFloatBinaryTransfer(ins Instr, form x86FloatBinaryForm, state *x86ResultState, owned []bool, arch string) bool {
	return x86ScalarFPFloatBinaryTransferWithRead(ins, form, state, owned, arch, false)
}

// Only the paired native emitter can supply an active source value after its
// exact access continues. Register, mask and merge inputs remain independent.
func x86ScalarFPFloatBinaryTransferWithRead(ins Instr, form x86FloatBinaryForm,
	state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if form.bits == 16 {
		original, valid := x86RawFP16BinarySourceForm(ins, arch)
		if !nativeRead || !valid || original.x86FloatBinaryForm != form {
			return false
		}
		// Only this local read consumes the paired access. Original identity
		// remains required and no raw/caller/memory permission escapes.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	} else if form.bits != 32 && form.bits != 64 {
		return false
	}
	width := int64(form.byteWidth)
	if form.scalar {
		width = int64(form.bits / 8)
	}
	required := x86CallerVectorByteMask(width)
	xreg := func(operand Operand) (int, bool) {
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		return index, operand.Kind == OpReg && valid && index < len(state.xmm) &&
			(arch != "386" || index < 8) && (!form.legacy || index < 16)
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	for _, input := range []int{form.first, form.second} {
		if form.literal && input == form.first {
			continue
		}
		if input == form.memory {
			// FP/AUTO have independently initialized logical byte envelopes.
			// A GP/SB native address cannot obtain authority from this query.
			if !x86ResultReadWithNativeContinuation(ins, ins.Args[input], int64(form.memoryBytes), state, owned, arch, nativeRead) {
				return false
			}
			continue
		}
		index, valid := xreg(ins.Args[input])
		if !valid || state.vectorBytes(index)&required != required {
			return false
		}
	}
	destination, valid := xreg(ins.Args[form.destination])
	if !valid {
		return false
	}
	old := state.vectorBytes(destination)
	if form.mask >= 0 && !form.zeroing && old&required != required {
		return false
	}
	known := x86CallerVectorByteMask(int64(form.byteWidth))
	if form.legacy {
		known = old | required
	} else if form.scalar {
		second, valid := xreg(ins.Args[form.second])
		if !valid {
			return false
		}
		known = required | state.vectorBytes(second)&^required
	}
	state.writeVector(destination, form.byteWidth, known, form.legacy)
	return true
}
