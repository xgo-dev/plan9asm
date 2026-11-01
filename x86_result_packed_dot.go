package plan9asm

// Zero is absent physical identity. Low-bank unmasked X/Y operands alone
// cannot distinguish an AVX-VNNI opcode from the EVEX Go source spelling.
type x86RawPackedDotEncoding uint8

const (
	x86RawPackedDotAbsent x86RawPackedDotEncoding = iota
	x86RawPackedDotVEX
	x86RawPackedDotEVEX
)

type x86RawPackedDotIdentity struct {
	arch     string
	encoding x86RawPackedDotEncoding
	encoded  bool
}

func x86PackedDotRawIdentity(ins Instr, arch string) x86RawPackedDotIdentity {
	if _, known, err := x86PackedDotProperties(ins.Op, ins, arch); !known || err != nil ||
		ins.x86PackedDotEncoding != x86RawPackedDotVEX && ins.x86PackedDotEncoding != x86RawPackedDotEVEX {
		return x86RawPackedDotIdentity{}
	}
	return x86RawPackedDotIdentity{arch, ins.x86PackedDotEncoding, ins.x86Encoded}
}

func x86RawPackedDotSource(ins Instr, arch string) bool {
	form, known, err := x86PackedDotProperties(ins.Op, ins, arch)
	return known && err == nil && ins.x86SourceRaw != nil &&
		ins.x86SourceRaw.packedDot.arch == arch &&
		ins.x86SourceRaw.packedDot == x86PackedDotRawIdentity(ins, arch) &&
		x86Mode32VectorRegisterContext(ins, arch) == nil &&
		x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

// Select the restriction from the immutable decoded source before any strict
// numerical success; deleting a mutable origin cannot invent a named source.
func x86PackedDotRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay != nil {
		for _, ins := range fn.x86RawReplay.decoded {
			if _, known, _ := x86PackedDotProperties(ins.Op, ins, arch); known {
				return true
			}
		}
	}
	return false
}

func x86ResultPackedDotStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86PackedDotProperties(ins.Op, ins, arch)
	if !known || err != nil || x86Mode32VectorRegisterContext(ins, arch) != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawPackedDotSource(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	} else if ins.x86PackedDotEncoding != x86RawPackedDotAbsent {
		return false, true // A named source cannot invent a decoder generation.
	}
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	var first uint64
	if source := ins.Args[form.first]; source.Kind == OpReg {
		index, _ := amd64VectorRegisterIndex(source.Reg, form.byteWidth)
		first = state.vectorBytes(index)
	} else {
		if !x86ResultReadWithNativeContinuation(ins, source, int64(form.memoryBytes), state, owned, arch, native) {
			return false, true
		}
		first = ^uint64(0) // Conditional input bytes, never a later memory fact.
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if !form.inputsDefined(first, state.vectorBytes(second), state.vectorBytes(destination)) {
		return false, true
	}
	state.writeVector(destination, form.byteWidth, x86CallerVectorByteMask(int64(form.byteWidth)), false)
	return true, true // FLAGS, DF, masks, pointers and storage are unchanged.
}

func x86CallerPackedDotStep(ins *Instr, form x86PackedDotForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if !x86ResultNamedPredicateInstruction(*ins) {
		return false // Raw source has no inherited caller capability.
	}
	if form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	first := ^uint64(0)
	if form.memory >= 0 {
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
			return false
		}
	} else {
		first = state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)]
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)]
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	if !form.inputsDefined(first, second, state.vectors[destination]) {
		return false
	}
	state.vectors[destination] = ^uint64(0)
	return true
}
