package plan9asm

// Opaque inputs identify ABI0 pointer components, not pointee allocations.
// They may be copied through full-width GP/local cells and pointer results.
// They never enter the private-SP address map or numerical initialized bytes.
// Boolean masks independently record bytes whose values are exactly zero/one.
// This is needed because an ABI0 bool occupies one byte, but LLVM uses i1.
func fixedLocalTransportRole(role goAMD64FrameTransport) bool {
	return role == goAMD64FrameNumericTransport || role == goAMD64FrameCompositeTransport
}

func fixedLocalTransportSlot(offset, width int64, slots []FrameSlot) (FrameSlot, int, bool) {
	for index, slot := range slots {
		switch slot.Type {
		case I1, I8, I16, I32, I64, Ptr:
		default:
			continue
		}
		if slot.Offset == offset && frameTypeSize(slot.Type, 8) == width {
			return slot, index, true
		}
	}
	return FrameSlot{}, 0, false
}

func fixedLocalBooleanShift(reg Reg) uint {
	if _, bits, alias := amd64ByteAlias(reg); alias {
		return bits / 8
	}
	return 0
}

func fixedLocalConstantBooleans(value int64, width int64) uint8 {
	var mask uint8
	for index := int64(0); index < width; index++ {
		if byte(uint64(value)>>uint(index*8)) <= 1 {
			mask |= 1 << uint(index)
		}
	}
	return mask
}

func fixedLocalBooleanRead(operand Operand, width int64, state *x86FixedLocalState) uint8 {
	if operand.Kind == OpImm {
		return fixedLocalConstantBooleans(operand.Imm, width)
	}
	if operand.Kind == OpReg {
		root, _ := x86CallerGP(operand.Reg)
		return state.booleans[root] >> fixedLocalBooleanShift(operand.Reg) & uint8((1<<uint(width))-1)
	}
	return 0
}

func fixedLocalMemoryBooleans(state *x86FixedLocalState, offset, width int64) uint8 {
	var mask uint8
	for index := int64(0); index < width; index++ {
		if state.booleanBytes.has(offset + index) {
			mask |= 1 << uint(index)
		}
	}
	return mask
}

func fixedLocalWriteBooleans(state *x86FixedLocalState, reg Reg, width int64, values uint8) {
	root, _ := x86CallerGP(reg)
	state.revokeRange(root) // Every GP write, including partial aliases, invalidates its old value.
	mask := x86CallerByteMask(reg, width)
	values <<= fixedLocalBooleanShift(reg)
	if width == 4 {
		mask, values = 255, values|240 // Architectural zero extension.
	}
	state.booleans[root] = state.booleans[root]&^mask | values&mask
}

func fixedLocalRevokeSpillRoles(state *x86FixedLocalState, offset, width int64) {
	for start := range state.addresses {
		if offset < start+8 && start < offset+width {
			delete(state.addresses, start)
		}
	}
	for start := range state.opaqueCells {
		if offset < start+8 && start < offset+width {
			delete(state.opaqueCells, start)
		}
	}
	state.booleanBytes.setRange(offset, width, false)
}

func fixedLocalConditionalSetStep(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int) (bool, error) {
	form, known, err := x86ConditionalSetProperties(ins.Op, *ins, "amd64")
	if !known {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, goAMD64FrameContext("fixed local SETcc lacks initialized flags or typed destination")
	}
	needed := x86ByteConditionFlags(form.condition)
	if err != nil || needed == 0 || state.flags&needed != needed {
		return fail()
	}
	destination := form.destination
	switch destination.Kind {
	case OpReg:
		root, valid := x86CallerGP(destination.Reg)
		if !valid || root == SP {
			return fail()
		}
		if _, private := state.pointers[root]; private {
			return fail()
		}
		delete(state.opaque, root)
		delete(state.constants, root)
		state.known[root] |= x86CallerByteMask(destination.Reg, 1)
		fixedLocalWriteBooleans(state, destination.Reg, 1, 1)
	case OpMem:
		offset, role, err := fixedLocalMemoryAccess(ins, 0, state, proof, residue, 1, 1, true, false)
		if err != nil {
			return true, err
		}
		if role == x86FixedLocalPrivateMemory {
			fixedLocalNumericalStore(state, offset, 1, true)
			state.booleanBytes.set(offset, true)
		}
	case OpFP:
		sp, original := state.pointers[SP]
		_, index, found := fixedLocalTransportSlot(destination.FPOffset, 1, sig.Frame.Results)
		if !original || sp != 0 || !found {
			return fail()
		}
		state.results[index] = true
	default:
		return fail()
	}
	return true, nil
}
