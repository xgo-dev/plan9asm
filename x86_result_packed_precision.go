package plan9asm

type x86RawPackedPrecisionIdentity struct {
	arch          string
	encoded, evex bool
}

func x86PackedPrecisionRawIdentity(ins Instr, arch string) x86RawPackedPrecisionIdentity {
	if _, known, err := x86PackedPrecisionProperties(ins.Op, ins, arch); !known || err != nil {
		return x86RawPackedPrecisionIdentity{}
	}
	return x86RawPackedPrecisionIdentity{arch, ins.x86Encoded, ins.x86PackedPrecisionEVEX}
}

func x86RawPackedPrecisionSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	return origin != nil && ins.x86Encoded && origin.packedPrecision.arch == arch &&
		origin.packedPrecision == x86PackedPrecisionRawIdentity(ins, arch) && x86RawOrdinaryVectorSource(ins, arch)
}

func x86PackedPrecisionRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay != nil {
		for _, ins := range fn.x86RawReplay.decoded {
			if _, known, _ := x86PackedPrecisionProperties(ins.Op, ins, arch); known {
				return true
			}
		}
	}
	return false
}

// Both actual source bytes and possible old active output bytes precede the
// single write. Upper carrier zeros do not read old bytes; CF/DF/ID, pointers
// and storage remain independent. Raw continuation is paired and source-bound.
func x86ResultPackedPrecisionStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86PackedPrecisionProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawPackedPrecisionSource(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86ResultPackedConversionInputs(ins, form, state, owned, arch, native), true
}
