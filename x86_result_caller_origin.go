package plan9asm

// A nonzero ID names one actual immutable typed-entry pointer slot. It carries
// no numerical bytes, extent, alignment, alias or pointee permission. Derived
// addresses retain that ID only after the existing complete transfer accepts
// their full-word operation and every numerical affine input.
func x86ResultCallerOriginsAfter(original Instr, before [16]uint16, after [16]bool,
	entryFP map[int64]bool, arch string) [16]uint16 {
	if len(entryFP) == 0 {
		return [16]uint16{} // A numerical-only entry cannot produce this domain.
	}
	next := before
	for index, address := range after {
		if !address {
			next[index] = 0
		}
	}
	ins := x86SourceMoveInstruction(original, arch)
	if !x86ResultNamedPredicateInstruction(ins) || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return next
	}
	word := x86ResultPointerWord(arch)
	if form, width, known, err := x86SwapProperties(ins, arch); known && err == nil &&
		width == word && form.other.Kind == OpReg {
		first, _, _ := x86ResultGP(form.register.Reg, width, arch)
		last, _, _ := x86ResultGP(form.other.Reg, width, arch)
		if after[first] {
			next[first] = before[last]
		}
		if after[last] {
			next[last] = before[first]
		}
		return next
	}
	destination, _, valid := x86ResultGP(ins.Args[1].Reg, word, arch)
	if !valid || !after[destination] {
		return next
	}
	move, lea, add := Op("MOVQ"), Op("LEAQ"), Op("ADDQ")
	if arch == "386" {
		move, lea, add = "MOVL", "LEAL", "ADDL"
	}
	first := ins.Args[0]
	switch ins.Op {
	case move, add:
		if ins.Op == add && before[destination] != 0 {
			return next // The ordinary pointer-destination order retains its origin.
		}
		next[destination] = 0
		if first.Kind == OpFP && first.FPOffset >= 0 && first.FPOffset < 4096 && entryFP[first.FPOffset] {
			next[destination] = uint16(first.FPOffset + 1)
		} else if first.Kind == OpReg {
			if source, _, valid := x86ResultGP(first.Reg, word, arch); valid {
				next[destination] = before[source]
			}
		}
	case lea:
		next[destination] = 0
		if first.Kind == OpMem && first.Mem.Sym == "" {
			if source, _, valid := x86ResultGP(first.Mem.Base, word, arch); valid {
				next[destination] = before[source]
			}
		}
	}
	return next
}

// Subtracting two full-word affine addresses from the same actual entry
// cancels their common opaque base. No unrelated address or transformed pointer
// bits become numerical. The normal lowerer retains the original subtraction,
// including all of its status flags; source instructions are never rewritten.
func x86ResultCallerAddressDifferenceStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	op := Op("SUBQ")
	if arch == "386" {
		op = "SUBL"
	}
	if ins.Op != op || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg ||
		state.shapeOnly && ins.Args[0].Kind != OpFP {
		return false, false
	}
	word := x86ResultPointerWord(arch)
	destination, _, last := x86ResultGP(ins.Args[1].Reg, word, arch)
	if !last || !state.shapeOnly && !state.callerAddressGP[destination] {
		return false, false
	}
	var origin uint16
	switch source := ins.Args[0]; source.Kind {
	case OpReg:
		index, _, valid := x86ResultGP(source.Reg, word, arch)
		if !valid || !state.callerAddressGP[index] {
			return false, false
		}
		origin = state.callerAddressOrigin[index]
	case OpFP:
		// Entry parameter slots are immutable in this proof. Only the exact
		// typed pointer field can cancel its own derived address; adjacent
		// numeric fields and partial pointer reads cannot borrow that origin.
		if source.FPOffset >= 0 && source.FPOffset < 4096 && state.callerAddressFP[source.FPOffset] {
			origin = uint16(source.FPOffset + 1)
		}
	default:
		return false, false
	}
	effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
	if !x86ResultNamedPredicateInstruction(ins) || !known || err != nil || effect.dynamicMemory ||
		origin == 0 || !state.shapeOnly && origin != state.callerAddressOrigin[destination] {
		return false, true
	}
	// The source-wide shape pass checks the exact typed FP field and grammar,
	// not an origin match. Its state never reaches a CFG edge; every actual
	// reaching transfer must independently prove the destination's origin.
	state.gp[destination] = 0xff
	state.canonicalGP[destination] = 0
	state.pointerGP[destination], state.callerAddressGP[destination] = false, false
	state.callerAddressOrigin[destination] = 0
	state.resultAddressGP[destination] = x86ResultSlotAddress{}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}

// This is only a cost predicate for requiring the existing complete cached
// source proof. A pointer declaration or a SUB spelling grants no origin or
// numerical result. The proof independently checks every actual source path.
func x86ResultCallerAddressDifferenceNeedsProof(ins Instr, sig FuncSig, arch string) bool {
	op := Op("SUBQ")
	if arch == "386" {
		op = "SUBL"
	}
	if ins.Op != op || !x86ResultNamedPredicateInstruction(ins) || len(ins.Args) != 2 ||
		(ins.Args[0].Kind != OpReg && ins.Args[0].Kind != OpFP) || ins.Args[1].Kind != OpReg {
		return false
	}
	if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); !known || err != nil {
		return false
	}
	for _, slot := range sig.Frame.Params {
		if slot.Type == Ptr && (ins.Args[0].Kind == OpReg || ins.Args[0].FPOffset == slot.Offset) {
			return true
		}
	}
	return false
}
