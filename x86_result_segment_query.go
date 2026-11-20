package plan9asm

// Numerical query results consume the shared selector and old-destination
// grammar. Only the paired lowering reader may continue a native m16 access;
// a declaration-only observer gains no pointer, storage or later-read fact.
func x86ResultSegmentQueryStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86SegmentQueryProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	effect, _, _ := x86TypedSegmentQueryByteEffect(ins.Op, ins, arch)
	for _, input := range effect.operands {
		if input.operand.Kind == OpReg {
			index, _, valid := x86ResultGP(input.operand.Reg, input.width, arch)
			if !valid || state.pointerGP[index] {
				return false, true
			}
		}
		if !x86ResultReadWithNativeContinuation(ins, input.operand, input.width, state, owned, arch, native) {
			return false, true
		}
	}
	if form.spec.bits != 0 {
		index, mask, valid := x86ResultGP(form.destination, int64(form.spec.bits/8), arch)
		if !valid {
			return false, true
		}
		// A failed query retains the old result. In particular a dword
		// conditional write cannot manufacture unknown upper-byte knowledge
		// through the ordinary unconditional MOVL zero-extension rule.
		state.gp[index] |= mask
		state.canonicalGP[index] &^= mask
		state.pointerGP[index], state.callerAddressGP[index] = false, false
		state.callerAddressOrigin[index] = 0
		state.resultAddressGP[index] = x86ResultSlotAddress{}
	}
	state.flags |= x86ByteFlagZF // All five other status flags, DF and ID are preserved.
	return true, true
}

func x86SegmentQueryCanonicalBytesAfter(ins Instr, before [16]uint8, arch string) ([16]uint8, bool) {
	form, known, err := x86SegmentQueryProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return before, false
	}
	if form.spec.bits != 0 {
		index, mask, valid := x86ResultGP(form.destination, int64(form.spec.bits/8), arch)
		if !valid {
			return [16]uint8{}, true
		}
		before[index] &^= mask // No new canonical high dword follows from a conditional write.
	}
	return before, true
}
