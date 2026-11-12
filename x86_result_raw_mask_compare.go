package plan9asm

func x86RawImmediatePackedCompareSource(ins Instr, arch string) bool {
	_, known, err := x86ImmediatePackedCompareProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSourceAt(ins, arch, 1)
}

func x86LoweredImmediatePackedCompareStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86ImmediatePackedCompareProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawImmediatePackedCompareSource(ins, arch) {
			return false, true
		}
		// The complete original selector and every operand remain bound.
		// Only this paired numerical transfer consumes a named local view.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86ResultVectorCompareTransfer(ins, form.x86PackedIntegerCompareForm, state, owned, arch, true)
}
