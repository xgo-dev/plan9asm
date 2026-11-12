package plan9asm

// Reuse the complete source grammars and their byte effects. This adapter adds
// independently replayed private-frame memory, typed native input addresses
// and separately bound literal reads; it never supplies caller or raw access.
func fixedLocalPackedMoveStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	form, known, err := amd64PackedVectorMoveProperties(*ins, "amd64")
	legacy := false
	alignment := int64(1)
	if !known {
		if original, recognized, originalErr := x86NonTemporalVectorProperties(ins.Op, *ins, "amd64"); recognized {
			known, err, legacy = true, originalErr, !original.spec.vector
			form = original.move
			if original.trap {
				return true, goAMD64FrameContext("fixed local non-temporal move has no numerical continuation")
			}
		}
	}
	if !known {
		original, recognized, originalErr := x86LegacyPackedMoveProperties(ins.Op, *ins, "amd64")
		if !recognized {
			return false, nil
		}
		known, err, legacy = true, originalErr, true
		form = amd64PackedVectorMoveForm{
			byteWidth: 16, destination: 1, mask: -1,
			memory: original.memory, memoryWrite: original.memoryWrite,
		}
		form.spec.aligned = original.aligned
	}
	if err != nil || form.undefinedOpcode() {
		return known, goAMD64FrameContext("fixed local packed move has no numerical continuation")
	}
	if form.spec.aligned {
		alignment = int64(form.byteWidth)
	}
	if form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return true, goAMD64FrameContext("fixed local packed move has an undefined mask")
	}
	width := int64(form.byteWidth)
	widthMask := x86CallerVectorByteMask(width)
	numerical := widthMask
	if form.memory == 0 {
		// The private proof does not model runtime mask values: require every
		// possible read byte. Lowering still executes the original masked
		// opcode, including its alignment and masked fault behavior.
		if _, _, err := fixedLocalReadMemory(ins, 0, state, proof, residue, width, alignment); err != nil {
			return true, err
		}
	} else {
		numerical = state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)] & widthMask
	}
	if form.memoryWrite {
		if numerical != widthMask {
			return true, goAMD64FrameContext("fixed local packed store has undefined source bytes")
		}
		offset, role, err := fixedLocalMemoryAccess(ins, form.memory, state, proof, residue, width, alignment, true, false)
		if err != nil {
			return true, err
		}
		// A runtime mask is not an all-one mask. A partial store may invalidate
		// a private pointer spill, but cannot initialize its retained bytes.
		if role == x86FixedLocalPrivateMemory {
			fixedLocalNumericalStore(state, offset, width, form.mask < 0)
		}
		return true, nil
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	previous := state.vectors[destination]
	numerical = form.definedActiveBytes(numerical, previous)
	if legacy {
		state.vectors[destination] = previous&^widthMask | numerical
	} else {
		state.vectors[destination] = ^widthMask | numerical
	}
	return true, nil
}

func fixedLocalNumericalStore(state *x86FixedLocalState, offset, width int64, complete bool) {
	fixedLocalRevokeSpillRoles(state, offset, width)
	if complete {
		state.bytes.setRange(offset, width, true)
	}
}

// KMOV supplies numerical predicates through its existing four-width grammar.
// Full-word private addresses never become mask values. Local reads/writes
// retain the same byte envelope and owner as every other fixed-frame access.
func fixedLocalMaskMoveStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	bits, known := amd64MaskMoveSpecs[ins.Op]
	if !known {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, goAMD64FrameContext("fixed local mask move has unproved shape or numerical bytes")
	}
	if !amd64MaskMoveOperandsValid(*ins, "amd64") {
		return fail()
	}
	width := int64(bits / 8)
	source, destination := ins.Args[0], ins.Args[1]
	if source.Kind == OpMem || source.Kind == OpSym {
		if _, _, err := fixedLocalReadMemory(ins, 0, state, proof, residue, width, 1); err != nil {
			return true, err
		}
	} else if amd64IsKOperand(source) {
		if !state.masks[source.Reg] {
			return fail()
		}
	} else if !fixedLocalNumericRead(source, width, state) {
		return fail()
	}
	if destination.Kind == OpMem {
		offset, role, err := fixedLocalMemoryAccess(ins, 1, state, proof, residue, width, 1, true, false)
		if err != nil {
			return true, err
		}
		if role == x86FixedLocalPrivateMemory {
			fixedLocalNumericalStore(state, offset, width, true)
		}
		return true, nil
	}
	if amd64IsKOperand(destination) {
		state.masks[destination.Reg] = true
		return true, nil
	}
	root, valid := x86CallerGP(destination.Reg)
	if !valid || root == SP {
		return fail()
	}
	// Every KMOV GP destination zero-extends to the full architectural word.
	delete(state.pointers, root)
	delete(state.opaque, root)
	delete(state.constants, root)
	fixedLocalWriteBooleans(state, destination.Reg, 8, 0)
	state.known[root] = 255
	return true, nil
}
