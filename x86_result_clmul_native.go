package plan9asm

// Immediate selector and both data inputs retain one original identity. A
// numerical lane selector is not a memory footprint or native-entry proof.
func x86RawCLMULSource(ins Instr, arch string) bool {
	f, known, err := x86CLMULProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSourceAt(ins, arch, f.source)
}

// The existing emitter preserves the complete native legacy m128 opcode and
// its alignment/fault effects, or the full volatile vector tuple without fault
// suppression. This conditional result grants no backing or reusable read fact;
// unknown selected register qwords still propagate unknown numerical outputs.
func x86LoweredCLMULStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	f, known, err := x86CLMULProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawCLMULSource(ins, arch) {
			return false, true
		}
		// Physical mode32 has four operands even though its named frontend
		// does not. Retain that captured form rather than reparsing locally.
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	return x86ResultCLMULTransfer(local, f, state, owned, arch, true)
}
