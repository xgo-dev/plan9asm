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
	if immediate >= 0 && immediate&(immediate+1) == 0 {
		return form, index, x86PointerMaskResidue
	}
	cleared := ^immediate
	if width == x86ResultPointerWord(arch) && cleared > 0 && cleared&(cleared+1) == 0 {
		return form, index, x86PointerMaskRoundDown
	}
	return form, index, x86PointerMaskNone
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
