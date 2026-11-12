package plan9asm

// Physical generation is part of the original raw identity, not an operand
// inference or a numerical permission. arch distinguishes an absent snapshot
// from a genuine VEX source whose EVEX flag is false.
type x86RawPackedMoveIdentity struct {
	arch          string
	encoded, evex bool
}

func x86PackedMoveRawIdentity(ins Instr, arch string) x86RawPackedMoveIdentity {
	if _, known, err := amd64PackedVectorMoveProperties(ins, arch); !known || err != nil {
		return x86RawPackedMoveIdentity{}
	}
	return x86RawPackedMoveIdentity{arch, ins.x86Encoded, ins.x86PackedVectorMoveEVEX}
}

func x86RawPackedMoveEncodingSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	return origin != nil && origin.packedMove.arch == arch &&
		origin.packedMove == x86PackedMoveRawIdentity(ins, arch)
}
