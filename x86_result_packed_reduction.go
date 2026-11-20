package plan9asm

type x86RawPackedReductionIdentity struct {
	arch    string
	encoded bool
}

func x86PackedReductionRawIdentity(ins Instr, arch string) x86RawPackedReductionIdentity {
	local := ins
	// The sole caller that creates this snapshot has already decoded actual
	// whole-source bytes. A raw physical dot can have four operands in mode32;
	// this does not alter the separate named frontend's three-operand limit.
	local.x86Encoded = true
	if _, known, err := x86PackedReductionProperties(local, arch); !known || err != nil {
		return x86RawPackedReductionIdentity{}
	}
	return x86RawPackedReductionIdentity{arch: arch, encoded: ins.x86Encoded}
}

// This consumes numerical bytes only. The paired whole opcode performs its
// full native read and exceptions even for imm=0 or a dead/zeroed result.
// It creates no pointer, backing, alignment, caller or later-read authority.
func x86ResultPackedReductionStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86PackedReductionProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	return x86ResultPackedReductionInputs(ins, form, state, owned, arch, native), true
}

func x86ResultPackedReductionInputs(ins Instr, form x86PackedReductionForm, state *x86ResultState, owned []bool, arch string, native bool) bool {
	required := form.inputBytes()
	for _, index := range []int{form.first, form.second} {
		operand := ins.Args[index]
		if index == form.memory {
			if form.legacy && operand.Kind == OpFP ||
				!x86ResultReadWithNativeContinuation(ins, operand, int64(form.byteWidth), state, owned, arch, native) {
				return false
			}
		} else {
			register, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
			if !valid || state.vectorBytes(register)&required != required {
				return false
			}
		}
	}
	destination, valid := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if !valid {
		return false
	}
	state.writeVector(destination, form.byteWidth, x86CallerVectorByteMask(int64(form.byteWidth)), form.legacy)
	return true
}

func x86RawPackedReductionSource(ins Instr, arch string) bool {
	form, known, err := x86PackedReductionProperties(ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && origin != nil && origin.packedReduction.arch == arch &&
		origin.packedReduction == x86PackedReductionRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

func x86LoweredRawPackedReductionStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86PackedReductionProperties(ins, arch)
	if !known || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if err != nil || !x86RawPackedReductionSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ResultPackedReductionInputs(local, form, state, owned, arch, true), true
}
