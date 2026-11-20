package plan9asm

// These byte transfers reuse the same grammar as lowering. Native reads are
// conditional numerical availability only: they grant no source, pointer,
// alignment, initialized pointee, extent or later-read fact. A native=true
// caller must pair the instruction with an observable architectural read.
func x86ResultAlternatingFloatStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86AlternatingFloatProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(local) {
		if !native || !x86RawAlternatingFloatSource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	read := native && (!form.legacy || form.memory >= 0 &&
		x86LegacyAlternatingRoundMemorySource(local, local.Args[form.first], arch))
	return x86ScalarFPFloatBinaryTransferWithRead(local, form, state, owned, arch, read), true
}

func x86RawAlternatingFloatSource(ins Instr, arch string) bool {
	form, known, err := x86AlternatingFloatProperties(ins, arch)
	return known && err == nil && !form.legacy && x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

// Only the existing source-local decoder, immutable source replay, DATA
// binding and independent raw-return owner can supply this literal role.
// It is not ordinary raw, incoming-pointer or later-read authority.
func x86RawRoundLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceIdentity(ins, arch) {
		return false
	}
	form, known, err := x86RoundProperties(ins, arch)
	return known && err == nil && form.spec.vector && form.memory &&
		ins.x86RIPMemoryRead.source == 1 && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

func x86ResultRoundStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86RoundProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	literal := x86RawRoundLiteralForm(ins, arch)
	if !x86ResultNamedPredicateInstruction(ins) && !literal || !x86ResultRead(ins.Args[0], 1, state, owned, arch) {
		return false, true
	}
	low := x86CallerVectorByteMask(int64(form.memoryBytes))
	if form.memory {
		if !x86ResultReadWithNativeContinuation(ins, form.source, int64(form.memoryBytes), state, owned, arch, native && (form.spec.vector || x86LegacyAlternatingRoundMemorySource(ins, form.source, arch))) {
			return false, true
		}
	} else {
		source, valid := amd64VectorRegisterIndex(form.source.Reg, form.byteWidth)
		if !valid || arch == "386" && source >= 8 || state.vectorBytes(source)&low != low {
			return false, true
		}
	}
	destination, valid := amd64VectorRegisterIndex(form.destination.Reg, form.byteWidth)
	if !valid || arch == "386" && destination >= 8 {
		return false, true
	}
	defined := low
	if form.spec.scalar {
		upper, valid := amd64ParseXReg(form.upper.Reg)
		if !valid || arch == "386" && upper >= 8 {
			return false, true
		}
		upperRequired := uint64(0xffff) &^ low
		if literal && state.vectorBytes(upper)&upperRequired != upperRequired {
			return false, true
		}
		defined |= state.vectorBytes(upper) & upperRequired
	}
	state.writeVector(destination, form.byteWidth, defined, !form.spec.vector)
	return true, true // All unrelated vector/GP/FLAGS/mask/storage facts survive.
}
