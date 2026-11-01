package plan9asm

// The decoder records both the actual physical mode and the explicit encoded
// marker. An absent zero snapshot cannot assert a named or raw generation.
type x86RawTernaryLogicIdentity struct {
	arch    string
	encoded bool
}

func x86TernaryLogicRawIdentity(ins Instr, arch string) x86RawTernaryLogicIdentity {
	form, known, err := x86TernaryLogicProperties(ins.Op, ins, arch)
	if !known || err != nil || !ins.x86Encoded || ins.x86VectorBytes != form.byteWidth {
		return x86RawTernaryLogicIdentity{}
	}
	return x86RawTernaryLogicIdentity{arch: arch, encoded: ins.x86Encoded}
}

func x86RawTernaryLogicSource(ins Instr, arch string) bool {
	_, known, err := x86TernaryLogicProperties(ins.Op, ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && origin != nil && origin.ternaryLogic.arch == arch &&
		origin.ternaryLogic == x86TernaryLogicRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, 1)
}

// An independently bound DATA owner retains its existing literal consumer.
// It is not an incoming pointer or an ordinary native source continuation.
func x86RawTernaryLogicLiteralForm(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) {
		return false
	}
	form, known, err := x86TernaryLogicProperties(ins.Op, ins, arch)
	return known && err == nil && form.memory == 1 &&
		ins.x86RIPMemoryRead.source == 1 && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}
