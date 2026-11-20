package plan9asm

type x86RawZeroExtendIdentity struct {
	arch    string
	encoded bool
}

func x86ZeroExtendRawIdentity(ins Instr, arch string) x86RawZeroExtendIdentity {
	form, known, err := x86PackedZeroExtendProperties(ins, arch)
	if !known || err != nil || !form.spec.vector {
		return x86RawZeroExtendIdentity{}
	}
	return x86RawZeroExtendIdentity{arch, ins.x86Encoded}
}

// Both physical generations have the same shrinking tuple and upper-zero
// effect. The complete raw producer retains their original bytes; this check
// binds the existing typed grammar, architecture and every original operand.
// It grants no caller, standalone-query, literal or physical-entry authority.
func x86RawZeroExtendSource(ins Instr, arch string) bool {
	form, known, err := x86PackedZeroExtendProperties(ins, arch)
	return known && err == nil && form.spec.vector && ins.x86SourceRaw != nil &&
		ins.x86SourceRaw.zeroExtend.arch == arch &&
		ins.x86SourceRaw.zeroExtend == x86ZeroExtendRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSource(ins, arch)
}

func x86ZeroExtendRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay != nil {
		for _, ins := range fn.x86RawReplay.decoded {
			if form, known, _ := x86PackedZeroExtendProperties(ins, arch); known && form.spec.vector {
				return true
			}
		}
	}
	return false
}
