package plan9asm

// Numerical result effects consume the same forms as the lowerer. Legacy
// arithmetic keeps its existing typed consumer; no caller or native-memory
// permission follows from knowing the bytes of a vector arithmetic result.
func x86ResultVectorArithmeticStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultVectorArithmeticStepWithRead(ins, state, owned, arch, false)
}

// Only the paired emitter may consume a continued native read. The complete
// tuple, mask, lane dependencies and wider aliases keep their existing rules.
func x86ResultVectorArithmeticStepWithRead(ins Instr, state *x86ResultState, owned []bool,
	arch string, nativeRead bool) (bool, bool) {
	parsed, known, err := x86PackedArithmeticProperties(ins.Op, ins, arch, x86PackedArithmeticAdd|x86PackedArithmeticSubtract)
	if !known {
		return false, false
	}
	form, bits := parsed.x86PackedBinaryForm, parsed.spec.laneBits
	if err != nil {
		return false, true
	}
	if form.legacy {
		return false, false
	}
	return x86ResultPackedLaneArithmeticStepWithRead(ins, form, bits, state, owned, arch, nativeRead), true
}
