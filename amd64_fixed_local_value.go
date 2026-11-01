package plan9asm

// Scalar transport carries one complete typed value, never additional memory
// permission. MOV, CMOV and XCHG share the same read/write boundaries; exchanges
// snapshot both operands before changing any register or private spill.
type fixedLocalScalarValue struct {
	address         int64
	pointer, opaque bool
	identity        x86FixedLocalOrigins
	booleans        uint8
	constant        int64
	constantKnown   bool
	bounds          x86UnsignedRange
	bounded         bool
}

// Selection retains only facts true of both possible values. Private offsets
// must agree. Opaque addresses share the same machine-address domain;
// joining them never supplies a numerical value or private-frame permission.
func mergeFixedLocalScalarValues(first, last fixedLocalScalarValue) (fixedLocalScalarValue, bool) {
	if first.pointer != last.pointer || first.opaque != last.opaque ||
		first.pointer && first.address != last.address {
		return fixedLocalScalarValue{}, false
	}
	if first.opaque {
		var valid bool
		first.identity, valid = first.identity.union(last.identity)
		if !valid {
			return fixedLocalScalarValue{}, false
		}
	}
	first.booleans &= last.booleans
	first.constantKnown = first.constantKnown && last.constantKnown && first.constant == last.constant
	first.bounded = first.bounded && last.bounded
	if first.bounded {
		first.bounds = first.bounds.hull(last.bounds)
	}
	return first, true
}

func fixedLocalReadValue(ins *Instr, index int, state *x86FixedLocalState, sig FuncSig,
	proof *x86FixedLocalProof, residue int, width int64, write bool) (fixedLocalScalarValue, error) {
	var value fixedLocalScalarValue
	fail := func() error { return goAMD64FrameContext("unproved fixed local scalar read") }
	source := ins.Args[index]
	switch source.Kind {
	case OpReg:
		value.address, value.pointer = state.pointers[source.Reg]
		value.identity, value.opaque = state.opaque[source.Reg]
		if value.opaque && !value.identity.valid() {
			return value, fail()
		}
		if value.pointer || value.opaque {
			if width != 8 {
				return value, fail()
			}
		} else if amd64VectorByteWidth(source.Reg) == 16 {
			if width != 8 || state.vectors[x86CallerVectorRoot(source.Reg)]&255 != 255 {
				return value, fail()
			}
		} else {
			if !fixedLocalNumericRead(source, width, state) {
				return value, fail()
			}
			value.constant, value.constantKnown = state.constants[source.Reg]
			// Narrow moves truncate or preserve a destination's old upper
			// bytes. They cannot transport a complete 64-bit address mask.
			value.constantKnown = value.constantKnown && width == 8
			value.bounds, value.bounded = state.ranges[source.Reg]
			value.bounded = value.bounded && width == 8
			value.booleans = fixedLocalBooleanRead(source, width, state)
		}
	case OpImm:
		if !fixedLocalNumericRead(source, width, state) {
			return value, fail()
		}
		value.constant, value.constantKnown = source.Imm, width == 8
		value.booleans = fixedLocalBooleanRead(source, width, state)
	case OpFP:
		sp, original := state.pointers[SP]
		slot, _, found := fixedLocalTransportSlot(source.FPOffset, width, sig.Frame.Params)
		if !original || sp != 0 || !found {
			return value, fail()
		}
		if slot.Type == Ptr {
			value.opaque, value.identity = true, fixedLocalOrigin(x86FixedLocalOrigin{parameter: slot.Offset})
		} else if slot.Type == I1 {
			value.booleans = 1
		}
	case OpSym:
		if write {
			return value, fail()
		}
		if _, _, err := fixedLocalReadMemory(ins, index, state, proof, residue, width, 1); err != nil {
			return value, err
		}
	case OpMem:
		memory, err := fixedLocalMemoryAddress(*ins, index, proof.frame)
		if err != nil {
			return value, err
		}
		offset, found := fixedLocalPrivateOffset(memory, state)
		if found {
			value.address, value.pointer = state.addresses[offset]
			value.identity, value.opaque = state.opaqueCells[offset]
		}
		if value.opaque && !value.identity.valid() {
			return value, fail()
		}
		if (value.pointer || value.opaque) && width != 8 {
			return value, fail()
		}
		offset, role, err := fixedLocalMemoryAccess(ins, index, state, proof, residue, width, 1, write, value.pointer || value.opaque)
		if err != nil {
			return value, err
		}
		if role == x86FixedLocalPrivateMemory && !value.pointer && !value.opaque {
			if write {
				if !state.bytes.all(offset, width) {
					return value, fail()
				}
			}
			value.booleans = fixedLocalMemoryBooleans(state, offset, width)
		}
	default:
		return value, fail()
	}
	return value, nil
}

func fixedLocalWriteValue(ins *Instr, index, sourceIndex int, value fixedLocalScalarValue, state *x86FixedLocalState,
	sig FuncSig, proof *x86FixedLocalProof, residue int, width int64) error {
	fail := func() error { return goAMD64FrameContext("unproved fixed local scalar write") }
	destination, source := ins.Args[index], ins.Args[sourceIndex]
	switch destination.Kind {
	case OpReg:
		root, valid := x86CallerGP(destination.Reg)
		if !valid || (value.pointer || value.opaque) && (width != 8 || destination.Reg != root) {
			return fail()
		}
		if root == SP && !value.pointer {
			return fail()
		}
		if _, oldPointer := state.pointers[root]; oldPointer && width != 8 {
			return fail()
		}
		delete(state.pointers, root)
		delete(state.opaque, root)
		delete(state.constants, root)
		fixedLocalWriteBooleans(state, destination.Reg, width, value.booleans)
		if value.pointer {
			state.pointers[root] = value.address
			state.known[root] = 0
		} else if value.opaque {
			state.opaque[root] = value.identity
			state.known[root] = 0
		} else {
			mask := x86CallerByteMask(destination.Reg, width)
			if mask == 0 {
				return fail()
			}
			if width == 4 {
				mask = 255
			}
			state.known[root] |= mask
			if value.constantKnown {
				state.constants[root] = value.constant
			}
			if value.bounded {
				state.setRange(root, value.bounds)
			}
		}
	case OpMem:
		if source.Kind == OpMem {
			return fail()
		}
		offset, role, err := fixedLocalMemoryAccess(ins, index, state, proof, residue, width, 1, true, false)
		if err != nil {
			return err
		}
		if role == x86FixedLocalNativeInput {
			if value.pointer || value.opaque {
				return fail() // Neither private nor input pointers escape as bytes.
			}
			return nil
		}
		fixedLocalRevokeSpillRoles(state, offset, width)
		state.bytes.setRange(offset, width, !value.pointer && !value.opaque)
		for index := offset; index < offset+width; index++ {
			state.booleanBytes.set(index, value.booleans&(1<<uint(index-offset)) != 0)
		}
		if value.pointer {
			state.addresses[offset] = value.address
		}
		if value.opaque {
			state.opaqueCells[offset] = value.identity
		}
	case OpFP:
		sp, original := state.pointers[SP]
		slot, index, found := fixedLocalTransportSlot(destination.FPOffset, width, sig.Frame.Results)
		if !original || sp != 0 || value.pointer || value.identity.hasLiteral() || !found || source.Kind != OpReg && source.Kind != OpImm ||
			value.opaque != (slot.Type == Ptr) || slot.Type == I1 && value.booleans&1 == 0 {
			return fail()
		}
		state.results[index] = true
	default:
		return fail()
	}
	return nil
}
