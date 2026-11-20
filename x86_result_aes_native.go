package plan9asm

func x86RawAESSource(ins Instr, arch string) bool {
	form, known, err := x86AESProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSourceAt(ins, arch, form.source)
}

// The complete AES grammar and byte dependencies are shared, not re-listed.
// The paired lowerer retains the original legacy m128 opcode/alignment fault,
// or the vector form's complete volatile read. Neither grants native backing.
func x86LoweredAESResultStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	_, known, err := x86AESProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawAESSource(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86ResultAESStepWithRead(ins, state, owned, arch, true)
}
