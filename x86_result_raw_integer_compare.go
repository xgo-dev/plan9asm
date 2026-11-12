package plan9asm

// The complete legacy X/VEX X/Y/EVEX K-result grammar remains independent of
// raw source authentication. Physical MMX/x87 regions, RIP literals, source
// frames and entry permissions retain their existing separate consumers.
func x86RawPackedIntegerCompareSource(ins Instr, arch string) bool {
	form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch)
	return known && err == nil && !form.mmx && x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

// Only the paired original opcode or exact volatile E4 accesses supply this
// conditional numerical result. Preserve the captured physical form before
// projecting provenance locally: mode32's real four-operand EVEX instruction
// must not be reparsed under the different named-frontend arity limit.
func x86LoweredPackedIntegerCompareStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86RawPackedIntegerCompareSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ResultVectorCompareTransfer(local, form, state, owned, arch, true)
}
