package plan9asm

// Physical generation belongs to the decoder's original source, not a low
// register spelling or a later numerical-input permission.
type x86RawPackedAbsIdentity struct {
	arch          string
	encoded, evex bool
}

func x86PackedAbsRawIdentity(ins Instr, arch string) x86RawPackedAbsIdentity {
	form, known, err := x86PackedAbsSignProperties(ins.Op, ins, arch)
	if !known || err != nil || form.legacy || form.spec.sign {
		return x86RawPackedAbsIdentity{}
	}
	return x86RawPackedAbsIdentity{arch, ins.x86Encoded, ins.x86PackedAbsEVEX}
}

// All four VPABS names retain the existing typed grammar and exact full or
// broadcast tuple. Only a replay-bound mode64 RIP literal participates: this
// supplies no ordinary-pointer, raw-entry, caller or standalone-query role.
func x86RawPackedAbsLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceIdentity(ins, arch) {
		return false
	}
	origin := ins.x86SourceRaw
	if origin.packedAbs.arch != arch || origin.packedAbs != x86PackedAbsRawIdentity(ins, arch) {
		return false
	}
	form, known, err := x86PackedAbsSignProperties(ins.Op, ins, arch)
	return known && err == nil && !form.legacy && !form.spec.sign && form.memory == form.first &&
		ins.x86RIPMemoryRead.source == form.first && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}
