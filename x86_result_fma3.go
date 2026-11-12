package plan9asm

// Ordinary named FMA3 consumes three numerical sources in every order. Its
// destructive destination remains an arithmetic input even with zero masking.
// The existing raw-only FP16 consumer owns a separate exact-source contract.
func x86ResultFMA3Step(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := amd64FMA3Properties(ins, arch)
	if !known || form.spec.rawOnly {
		return false, false
	}
	if err != nil {
		return false, true
	}
	literal := x86RawFMA3LiteralForm(ins, arch)
	if !literal && (!x86ResultNamedPredicateInstruction(ins) || ins.x86FMA3Encoding != x86RawFMA3Absent) {
		if !nativeRead || !x86RawFMA3Source(ins, arch) {
			return false, true
		}
		// Project only this paired access. Keep the complete physical form so
		// mode32 masks do not get reparsed through Go's named arity limit.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86ResultFMA3Inputs(ins, form, state, owned, arch, nativeRead), true
}

func x86ResultFMA3Inputs(ins Instr, form amd64FMA3Form, state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false
		}
	}
	active := form.byteWidth
	if form.spec.scalar {
		active = form.spec.laneBits / 8
	}
	required := x86CallerVectorByteMask(int64(active))
	for _, index := range []int{0, 1, form.destination} {
		if index == form.memory {
			if !x86ResultReadWithNativeContinuation(ins, ins.Args[index], int64(form.memoryBytes), state, owned, arch, nativeRead) {
				return false
			}
			continue
		}
		register, _ := amd64VectorRegisterIndex(ins.Args[index].Reg, form.byteWidth)
		if state.vectorBytes(register)&required != required {
			return false
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	knownBytes := ^uint64(0)
	if form.spec.scalar {
		// Unlike scalar binary arithmetic, FMA's upper-X passthrough comes
		// from the old destructive destination, not either explicit source.
		knownBytes = required | state.vectorBytes(destination)&(0xffff&^required)
	}
	state.writeVector(destination, form.byteWidth, knownBytes, false)
	return true
}
