package plan9asm

func x86RawAccumulatorSignExtendSource(ins Instr, arch string) bool {
	_, known, err := x86AccumulatorSignExtendProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOperandFreeSource(ins)
}

// Only the exact decoded implicit GP instruction shares the named byte effect.
// This creates neither a raw entry nor a caller, frame or declaration-query role.
func x86LoweredAccumulatorSignExtendResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	_, known, _ := x86AccumulatorSignExtendProperties(ins.Op, ins, arch)
	if !known || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if !x86RawAccumulatorSignExtendSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ResultTransfer(local, state, owned, resultOffset, arch), true
}
