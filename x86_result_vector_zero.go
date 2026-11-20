package plan9asm

func x86RawVectorZeroSource(ins Instr, arch string) bool {
	_, known, err := x86VectorZeroProperties(ins, arch)
	return known && err == nil && x86RawOperandFreeSource(ins)
}

// Only the exact decoded implicit write shares the existing complete-bank
// effect. Preserved low/high bytes stay unknown; no memory or entry role follows.
func x86LoweredVectorZeroResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	_, known, _ := x86VectorZeroProperties(ins, arch)
	if !known || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if !x86RawVectorZeroSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ResultTransfer(local, state, owned, resultOffset, arch), true
}
