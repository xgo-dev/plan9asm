package plan9asm

// A zero identity is absent, not an assertion of legacy/VEX generation.
// The decoder captures physical mode and EVEX separately from a named form's
// inferred ISA needs. This snapshot grants no numerical or native entry facts.
type x86RawScalarFloatIntegerIdentity struct {
	arch          string
	encoded, evex bool
}

func x86ScalarFloatIntegerRawIdentity(ins Instr, arch string) x86RawScalarFloatIntegerIdentity {
	form, known, err := x86ScalarFloatIntegerProperties(ins, arch)
	if !known || err != nil || form.evex != ins.x86ScalarFloatIntegerEVEX {
		return x86RawScalarFloatIntegerIdentity{}
	}
	return x86RawScalarFloatIntegerIdentity{arch, ins.x86Encoded, ins.x86ScalarFloatIntegerEVEX}
}

// Validate the complete current form against its immutable physical snapshot.
// The whole-function replay separately authenticates all original producers;
// neither identity supplies an absent pointer, index, vector or MXCSR input.
func x86RawScalarFloatIntegerSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	identity := x86ScalarFloatIntegerRawIdentity(ins, arch)
	return origin != nil && identity.arch == arch && origin.scalarFloatInteger == identity &&
		x86RawOrdinaryVectorSource(ins, arch)
}
