package plan9asm

type x86PointerMaskKind uint8

const (
	x86PointerMaskNone x86PointerMaskKind = iota
	x86PointerMaskResidue
	x86PointerMaskRoundDown
)

// Interpret the immediate after the shared AND grammar has applied its
// encoding width and resolved the destination's physical register.
func x86PointerMaskProperties(ins Instr, arch string) (x86LockScalarRMWForm, int, x86PointerMaskKind) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86LockScalarRMWForm{}, 0, x86PointerMaskNone
	}
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	if !known || err != nil || form.spec.stem != "AND" || form.source.Kind != OpImm || form.destination.Kind != OpReg {
		return form, 0, x86PointerMaskNone
	}
	width := int64(form.spec.bits / 8)
	index, _, valid := x86ResultGP(form.destination.Reg, width, arch)
	if !valid {
		return form, 0, x86PointerMaskNone
	}
	immediate := form.source.Imm
	if x86LowImmediateMask(immediate) {
		return form, index, x86PointerMaskResidue
	}
	cleared := ^immediate
	if width == x86ResultPointerWord(arch) && cleared > 0 && cleared&(cleared+1) == 0 {
		return form, index, x86PointerMaskRoundDown
	}
	return form, index, x86PointerMaskNone
}

func x86LowImmediateMask(value int64) bool {
	return value >= 0 && value&(value+1) == 0
}

func x86ResultPointerMaskStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	if state.shapeOnly {
		return false, false
	}
	form, index, kind := x86PointerMaskProperties(ins, arch)
	if kind == x86PointerMaskNone || !state.pointerGP[index] || !state.callerAddressGP[index] {
		return false, false
	}
	if kind == x86PointerMaskResidue {
		if !x86ResultStore(form.destination, int64(form.spec.bits/8), state, owned, resultOffset, arch) {
			return false, true
		}
		// The low-bit projection is numerical and drops its address identity.
		state.callerAddressGP[index], state.pointerGP[index] = false, false
		state.callerAddressOrigin[index] = 0
	} else {
		state.gp[index] = 0
	}
	// Rounding down retains an entry-derived address. The exact native
	// access still owns faults; alignment, bounds and pointee bytes remain
	// independent of this effect.
	state.resultAddressGP[index] = x86ResultSlotAddress{}
	state.canonicalGP[index] = 0
	state.predicate = x86ResultPredicate{}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true
}

// A bitwise XOR with a bounded low-bit numerical value changes only the
// address residue. Retain the original pointer identity and its existing
// source permission, without acquiring a logical-frame alias or extent.
func x86ResultMaskedPointerXOR(ins Instr, state *x86ResultState, owned []bool, arch string) (int, bool) {
	if ins.Op != "XORQ" && ins.Op != "XORL" || state.shapeOnly || !x86ResultNamedPredicateInstruction(ins) {
		return 0, false
	}
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	word := x86ResultPointerWord(arch)
	if !known || err != nil || int64(form.spec.bits/8) != word || form.destination.Kind != OpReg {
		return 0, false
	}
	destination, _, valid := x86ResultGP(form.destination.Reg, word, arch)
	if !valid || !state.pointerGP[destination] || !state.callerAddressGP[destination] {
		return 0, false
	}
	switch source := form.source; source.Kind {
	case OpImm:
		if !x86LowImmediateMask(source.Imm) {
			return 0, false
		}
	case OpReg:
		index, _, valid := x86ResultGP(source.Reg, word, arch)
		if !valid || index == destination || state.lowMasks&(1<<uint(index)) == 0 ||
			!x86ResultRead(source, word, state, owned, arch) {
			return 0, false
		}
	default:
		return 0, false
	}
	state.gp[destination], state.canonicalGP[destination] = 0, 0
	state.resultAddressGP[destination] = x86ResultSlotAddress{}
	if state.boolFrameGP != nil {
		state.boolFrameGP[destination] = x86ResultSlotAddress{}
	}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return destination, true
}

// Called only after the real transfer accepts. A full L/Q AND with a low
// immediate sets the fact; any write to an overlapping GP view kills it.
func (state *x86ResultState) updateLowMasks(ins Instr, arch string) {
	producer := ins.Op == "ANDL" || ins.Op == "ANDQ"
	if state.lowMasks == 0 && !producer {
		return
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		state.lowMasks = 0
		return
	}
	if ins.Op == OpJMP || x86BranchCondition(ins.Op) != "" {
		return // FLAGS-based branches have no GP output.
	}
	ins = x86SourceMoveInstruction(ins, arch)
	effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
	if !known || err != nil || effect.dynamicMemory {
		state.lowMasks = 0
		return
	}
	for _, operand := range effect.operands {
		if operand.write && operand.operand.Kind == OpReg {
			if index, _, valid := x86ResultGP(operand.operand.Reg, operand.width, arch); valid {
				state.lowMasks &^= 1 << uint(index)
			}
		}
	}
	if producer {
		_, index, kind := x86PointerMaskProperties(ins, arch)
		if kind == x86PointerMaskResidue {
			state.lowMasks |= 1 << uint(index)
		}
	}
}
