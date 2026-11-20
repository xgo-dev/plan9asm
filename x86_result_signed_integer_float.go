package plan9asm

// The complete signed conversion grammar supplies a defined low scalar from
// every native integer source byte. Unwritten merge bytes keep their actual
// sparse knowledge, not a guessed zero or a requirement to read the whole X.
// Only the paired volatile native read may supply conditional numerical bytes;
// the descriptor never grants pointee, caller, frame, alignment or entry roles.
func x86ResultSignedIntegerFloatStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultSignedIntegerFloatStepWithRead(ins, state, owned, arch, false)
}

func x86ResultSignedIntegerFloatStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86SignedIntegerFloatProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86ResultIntegerScalarFloatInputs(ins, form, state, owned, arch, nativeRead), true
}

func x86ResultIntegerScalarFloatInputs(ins Instr, form x86SignedIntegerFloatForm, state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if !x86ResultNamedPredicateInstruction(ins) {
		return false
	}
	width := int64(form.sourceBits / 8)
	source := ins.Args[0]
	if source.Kind == OpReg {
		index, _, valid := x86ResultGP(source.Reg, width, arch)
		if !valid || state.pointerGP[index] || state.callerAddressGP[index] {
			return false
		}
	}
	if !x86ResultReadWithNativeContinuation(ins, source, width, state, owned, arch, nativeRead) {
		return false
	}
	upper, _ := amd64ParseXReg(ins.Args[form.upper].Reg)
	destination, _ := amd64ParseXReg(ins.Args[form.destination].Reg)
	low := x86CallerVectorByteMask(int64(form.spec.resultBits / 8))
	merge := state.vectorBytes(upper) & (0xffff &^ low)
	state.writeVector(destination, 16, low|merge, form.spec.legacy)
	return true // Integer status and DF remain unchanged; MXCSR is native.
}
