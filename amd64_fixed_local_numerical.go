package plan9asm

// Only an exact private read certificate supplies the SB bytes. The local
// proof learns numerical definedness, never a constant, pointer or address.
func fixedLocalNumericalReadStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	if ins.x86NumericalRead == nil {
		return false, nil
	}
	if _, form, valid := numericalCertifiedRead(*ins, "amd64"); valid && form.spec.vector != x86NumericalSBScalar {
		if !numericalVectorMapStep(*ins, "amd64", form, state.vectors, state.masks) {
			return true, goAMD64FrameContext("fixed local numerical vector read needs its complete typed inputs")
		}
		return true, nil
	}
	effect, valid := x86NumericalReadEffect(*ins, "amd64")
	if !valid {
		return true, goAMD64FrameContext("fixed local numerical read certificate changed")
	}
	return true, fixedLocalTypedByteStep(ins, state, FuncSig{}, proof, residue, effect)
}
