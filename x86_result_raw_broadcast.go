package plan9asm

// Scalar, block and K-data broadcasts share the complete typed grammar. This
// checks original source identity, not numerical inputs or native backing;
// RIP literals, logical fields and raw entry retain their separate consumers.
func x86RawBroadcastSource(ins Instr, arch string) bool {
	_, known, err := x86BroadcastProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

// Only the paired emitter's exact E6 accesses supply conditional native input.
// Capture its complete physical form before projecting provenance locally:
// numeric GP bits, actual K data, masks and old/source vector bytes remain
// independent obligations, including dead outputs and mode32 GP-Q WIG forms.
func x86LoweredRawBroadcastStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	f, known, err := x86BroadcastProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86RawBroadcastSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ResultBroadcastTransfer(local, f, state, owned, arch, true, false)
}
