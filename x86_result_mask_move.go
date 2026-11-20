package plan9asm

func x86RawMaskMoveSource(ins Instr, arch string) bool {
	_, known, err := x86TypedMaskMoveByteEffect(ins.Op, ins, arch)
	if !known || err != nil || ins.x86Encoded || !x86RawOrdinaryVectorSource(ins, arch) {
		return false
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg && !x86RegisterAddressedNativeMemoryOperand(operand, arch) {
			return false // Decoded native operands cannot borrow FP, SB, literal or frame roles.
		}
	}
	return true
}

// Native continuation belongs only to lowering paired with the exact volatile
// access. Standalone declaration, caller and frame observers retain their own
// storage contracts; an incoming pointer never asserts backing or bounds.
func x86MaskMoveResultStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string, native bool) (bool, bool) {
	form, known, err := x86MaskMoveProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, false
	}
	width := int64(form.bits / 8)
	first, last := ins.Args[0], ins.Args[1]
	// Whole-source replay is checked before the paired lowering consumer.
	// Exact raw identity shares only the named emitter's volatile access;
	// original source/provenance and all numerical inputs remain unchanged.
	pairedNative := native && ins.x86NumericalRead == nil &&
		(x86ResultNamedPredicateInstruction(ins) || x86RawMaskMoveSource(ins, arch))
	if form.source == x86MaskMoveK {
		index, _ := amd64ParseKReg(first.Reg)
		if !state.masks[index] {
			return false, true
		}
	} else if !x86ResultRead(first, width, state, owned, arch) {
		if !pairedNative || !x86RegisterAddressedNativeMemoryOperand(first, arch) ||
			!x86ResultIncomingPointerReadAddressIdentity(first, state, arch) {
			return false, true
		}
	}
	if form.destination == x86MaskMoveK {
		index, _ := amd64ParseKReg(last.Reg)
		state.masks[index] = true
		return true, true
	}
	if pairedNative &&
		x86OrdinaryNativeMemoryOperand(last, arch) && x86ResultIncomingPointerAddressIdentity(last, state, arch) {
		return true, true // Native stores establish no reusable memory facts.
	}
	if last.Kind == OpReg {
		// KMOV's GP encoding zero-extends B/W/D, unlike partial MOVB/W.
		word := x86ResultPointerWord(arch)
		if width < word {
			width = word
		}
	}
	return x86ResultStore(last, width, state, owned, resultOffset, arch), true
}
