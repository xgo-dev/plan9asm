package plan9asm

func x86RawDwordProductResultSource(ins Instr, arch string) bool {
	form, known, err := x86DwordProductProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && x86RawOrdinaryVectorSource(ins, arch)
}

// The decoder's exact original opcode and operands permit only this paired
// numerical continuation. Declaration queries and raw entries gain nothing.
func x86LoweredDwordProductResultStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86DwordProductProperties(ins.Op, ins, arch)
	if !known || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if err != nil || !x86RawDwordProductResultSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ResultFixedVectorInputsWithRead(local, form.x86PackedBinaryForm, false, state, owned, arch, true), true
}
