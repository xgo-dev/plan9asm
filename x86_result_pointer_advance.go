package plan9asm

// This is the existing complete unary grammar projected onto a native-word
// affine address transform. Narrow writes and physical SP/amd64 BP retain
// their independent roles. The shape alone never creates an address identity.
func x86CallerPointerAdvanceProperties(ins Instr, arch string) (x86LockScalarRMWForm, bool) {
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) ||
		form.spec.stem != "INC" && form.spec.stem != "DEC" ||
		int64(form.spec.bits/8) != x86ResultPointerWord(arch) || form.destination.Kind != OpReg {
		return form, false
	}
	_, _, valid := x86ResultGP(form.destination.Reg, int64(form.spec.bits/8), arch)
	return form, valid
}

func x86ResultCallerPointerAdvanceStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	form, known := x86CallerPointerAdvanceProperties(ins, arch)
	if !known || state.shapeOnly {
		return false, false
	}
	index, _, _ := x86ResultGP(form.destination.Reg, int64(form.spec.bits/8), arch)
	if !state.pointerGP[index] || !state.callerAddressGP[index] {
		return false, false // An opaque literal carrier is not an actual caller address.
	}
	// INC/DEC does not consume CF to compute its address. Preserve exactly its
	// prior defined/unknown status; every other status bit is defined, DF is
	// unchanged, and no numerical bytes or new native memory identity appear.
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true
}
