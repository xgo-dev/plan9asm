package plan9asm

// Only the existing validated explicit IMUL descriptor is consumed here. This
// supplies byte-definedness, not a new pointer, frame or memory capability.
func x86CallerExplicitIMULStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof) (recognized, valid bool) {
	if _, known, err := x86ExplicitIMULProperties(ins.Op, *ins, "amd64"); !known || err != nil {
		return known, false
	}
	effect, known, err := x86TypedGPByteEffect(ins.Op, *ins, "amd64")
	if !known || err != nil || effect.dynamicMemory {
		return true, false
	}
	// All ordered source bytes (including the two-operand old destination)
	// must be defined before any destination can overwrite their evidence.
	for _, operand := range effect.operands {
		if !operand.read {
			continue
		}
		if operand.operand.Kind == OpMem {
			if proof == nil || !x86CallerOrdinaryMemoryStep(ins, operand.index, state, proof, operand.width, false) {
				return true, false
			}
		} else if !x86CallerNumericRead(operand.operand, operand.width, state) {
			return true, false
		}
	}
	for _, operand := range effect.operands {
		if operand.write && (operand.operand.Kind != OpReg || !x86CallerNumericWrite(operand.operand.Reg, operand.width, state)) {
			return true, false
		}
	}
	return true, true
}

func x86SourceStackNumericFlagMask(state *x86SourceStackState) uint8 {
	if state.numericFlags {
		return x86ByteFlagsAll // Preserve the pre-existing complete-flags witness.
	}
	return state.partialNumericFlags
}

func x86SourceStackNumericFlagsRead(state *x86SourceStackState, required uint8) bool {
	return required != 0 && x86SourceStackNumericFlagMask(state)&required == required
}

func x86SourceStackSetNumericFlags(state *x86SourceStackState, mask uint8) {
	state.numericFlags = mask == x86ByteFlagsAll
	state.partialNumericFlags = 0
	if !state.numericFlags {
		state.partialNumericFlags = mask
	}
}
