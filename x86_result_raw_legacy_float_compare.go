package plan9asm

// Legacy compare opcodes have a different immediate position from VCMP and
// different packed alignment/scalar passthrough effects. Bind their complete
// decoded identity before reusing the existing numerical family. The original
// native opcode, not a mathematical predicate projection, owns MXCSR and faults.
type x86RawLegacyFloatCompareIdentity struct {
	arch    string
	encoded bool
}

func x86LegacyFloatCompareRawIdentity(ins Instr, arch string) x86RawLegacyFloatCompareIdentity {
	form, known, err := x86FloatCompareProperties(ins, arch)
	if !known || err != nil || !form.legacy {
		return x86RawLegacyFloatCompareIdentity{}
	}
	return x86RawLegacyFloatCompareIdentity{arch: arch, encoded: ins.x86Encoded}
}

func x86RawLegacyFloatCompareSource(ins Instr, arch string) bool {
	form, known, err := x86FloatCompareProperties(ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && form.legacy && origin != nil &&
		origin.legacyFloatCompare.arch == arch &&
		origin.legacyFloatCompare == x86LegacyFloatCompareRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}
