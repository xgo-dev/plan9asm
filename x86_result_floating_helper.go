package plan9asm

// This transfer is paired with the complete native helper instruction. It
// preserves MXCSR/fault behavior in lowering and proves numerical bytes only;
// no pointee validity, caller extent, physical entry or storage owner follows.
func x86ResultFloatingHelperStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86FloatingHelperProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	if form.mask >= 0 {
		mask, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[mask] {
			return false, true
		}
	}
	required := x86CallerVectorByteMask(int64(form.activeBytes()))
	first := ins.Args[form.first]
	if form.memory >= 0 {
		if !form.spec.scalar && first.Kind == OpFP ||
			!x86ResultReadWithNativeContinuation(ins, first, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false, true
		}
	} else {
		source, valid := amd64VectorRegisterIndex(first.Reg, form.byteWidth)
		if !valid || state.vectorBytes(source)&required != required {
			return false, true
		}
	}
	upper := uint64(0)
	if form.second >= 0 {
		second, valid := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
		if !valid {
			return false, true
		}
		upper = state.vectorBytes(second)
		if form.spec.second && upper&required != required {
			return false, true
		}
	}
	if form.spec.maskResult {
		destination, valid := amd64ParseKReg(ins.Args[form.destination].Reg)
		if !valid {
			return false, true
		}
		state.masks[destination] = true
		return true, true // K destinations are write-only, never merge inputs.
	}
	destination, valid := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if !valid || (form.spec.readDestination || form.mask >= 0 && !form.properties.zeroing) &&
		state.vectorBytes(destination)&required != required {
		return false, true
	}
	defined := ^uint64(0)
	if form.spec.scalar {
		defined = ^uint64(0xffff) | required | upper&(0xffff&^required)
	}
	state.writeVector(destination, form.byteWidth, defined, false)
	return true, true // GP, FLAGS, DF/ID, masks and independent storage survive.
}
