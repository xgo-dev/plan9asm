package plan9asm

// This value snapshot is copied with its sealed raw origin, including immutable
// whole-source replay clones. No default false value identifies a conversion:
// arch is present only after its complete typed physical shape validates.
type x86RawPackedConversionIdentity struct {
	arch               string
	encoded, evex, mmx bool
}

func x86PackedConversionRawIdentity(ins Instr, arch string) x86RawPackedConversionIdentity {
	_, signed, signedErr := x86SignedPackedFloatProperties(ins, arch)
	_, numeric, numericErr := x86PackedConversionProperties(ins, arch)
	if !signed && !numeric || signed && signedErr != nil || numeric && numericErr != nil {
		return x86RawPackedConversionIdentity{}
	}
	return x86RawPackedConversionIdentity{
		arch: arch, encoded: ins.x86Encoded,
		evex: ins.x86PackedNumericEVEX, mmx: ins.x86MMXSourceConversion,
	}
}

func x86RawPackedConversionSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	if origin == nil || origin.packedConversion.arch != arch ||
		origin.packedConversion != x86PackedConversionRawIdentity(ins, arch) ||
		!x86RawOrdinaryVectorSource(ins, arch) {
		return false
	}
	if form, known, err := x86SignedPackedFloatProperties(ins, arch); known {
		return err == nil && !form.mmx
	}
	form, known, err := x86PackedConversionProperties(ins, arch)
	return known && err == nil && !form.mmx
}

// Only an exact original physical conversion may project into its existing
// numerical byte effect. The paired original native opcode retains MXCSR,
// exceptions, complete memory accesses and all mask/merge obligations. This
// projection creates no entry, caller, pointee, frame or reusable read fact.
func x86LoweredPackedConversionResultStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	_, signed, _ := x86SignedPackedFloatProperties(ins, arch)
	_, numeric, _ := x86PackedConversionProperties(ins, arch)
	if !signed && !numeric || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if !x86RawPackedConversionSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	if signed {
		return x86ResultSignedPackedFloatStep(local, state, owned, arch, true)
	}
	return x86ResultPackedConversionStepWithRead(local, state, owned, arch, true)
}
