package plan9asm

import "math"

// A full-word LEA keeps the same private-frame identity with a checked offset.
// It does not read memory or initialize numerical bytes; the later access must
// still establish its width, bounds, alignment and reaching initialized bytes.
func fixedLocalPrivateAddressStep(ins Instr, state *x86FixedLocalState, proof *x86FixedLocalProof) (bool, error) {
	view := ins
	if derived, known, err := x86NamedFrameMoveAddressInstruction(ins, "amd64"); known {
		if err != nil {
			return true, goAMD64FrameContext("fixed local original MOV address grammar is not closed")
		}
		view = derived
	}
	if x86LEAWidth(view.Op, "amd64") == 0 || len(view.Args) != 2 || view.Args[0].Kind != OpMem {
		return false, nil
	}
	if _, private := state.pointers[view.Args[0].Mem.Base]; !private {
		return false, nil
	}
	if proof == nil || ins.x86AddressBits != 0 {
		return true, goAMD64FrameContext("fixed local LEA requires the original native address width and frame")
	}
	width, err := x86LEAOperandWidth(view, "amd64")
	address, addressErr := fixedLocalMemoryAddress(ins, 0, proof.frame)
	offset, known := fixedLocalPrivateOffset(address, state)
	destination := ins.Args[1].Reg
	if err != nil || addressErr != nil || !known || destination == SP {
		return true, goAMD64FrameContext("fixed local LEA requires an original private address and checked numerical displacement")
	}
	delete(state.opaque, destination)
	delete(state.constants, destination)
	delete(state.booleans, destination)
	state.revokeRange(destination)
	if width == 8 {
		state.known[destination] = 0
		state.pointers[destination] = offset
	} else {
		// Truncated address bytes remain unknown. They cannot be reused as
		// NUM or as a pointer; W preserves old upper bytes and L zeroes them.
		delete(state.pointers, destination)
		state.known[destination] &^= x86CallerByteMask(destination, width)
		if width == 4 {
			state.known[destination] = 0xf0
		}
	}
	return true, nil
}

// Full-word affine operations preserve an actual typed input's identity, not
// numerical pointer bytes, pointee bounds or private-frame ownership. Grammar,
// widths and FLAGS come from the same typed forms as ordinary GP lowering.
func fixedLocalInputAddressStep(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int) (bool, error) {
	// A typed FP source can introduce the first native address. Otherwise no
	// address operation is possible before a register or spill carries one.
	if len(state.opaque) == 0 && len(state.opaqueCells) == 0 &&
		(len(ins.Args) == 0 || ins.Args[0].Kind != OpFP) {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, goAMD64FrameContext("fixed local affine input lacks a unique pointer and numerical offset: %s", ins.Op)
	}
	write := func(destination Operand, origin x86FixedLocalOrigins, killed, defined uint8) (bool, error) {
		root, valid := x86CallerGP(destination.Reg)
		if destination.Kind != OpReg || !valid || root != destination.Reg || root == SP {
			return fail()
		}
		writeFixedLocalOrigin(state, root, origin)
		state.flags = state.flags&^killed | defined
		if killed|defined != 0 {
			state.comparison = x86FixedLocalComparison{}
		}
		return true, nil
	}
	shift := func(origins x86FixedLocalOrigins, operand Operand, subtract bool) (x86FixedLocalOrigins, bool) {
		if !fixedLocalOriginOwners(origins, proof) {
			return origins, false
		}
		if origins.address.symbol == "" {
			return origins, true // Actual native arithmetic supplies no pointee bound.
		}
		delta, known := operand.Imm, operand.Kind == OpImm && operand.ImmRaw == "" && !operand.ImmIsFloat
		if operand.Kind == OpReg {
			delta, known = state.constants[operand.Reg]
		}
		if !known || subtract && delta == math.MinInt64 {
			origins.address = x86StaticSBAddress{}
			return origins, true
		}
		if subtract {
			delta = -delta
		}
		origins.address.offset += delta // Match the emitted wrapping i64 address arithmetic.
		return origins, true
	}
	if !x86ResultNamedPredicateInstruction(*ins) {
		return false, nil
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, *ins, "amd64"); known && err == nil && form.spec.bits == 64 {
		origin, pointer := fixedLocalOpaqueRegister(form.destination, state)
		switch form.spec.stem {
		case "ADD", "SUB", "ADC", "SBB":
			if form.destination.Kind != OpReg {
				return false, nil
			}
			carry := form.spec.carryInput
			if carry && state.flags&x86ByteFlagCF == 0 {
				return fail()
			}
			subtract := form.spec.stem == "SUB" || form.spec.stem == "SBB"
			value, err := fixedLocalReadValue(ins, 0, state, sig, proof, residue, 8, false)
			if err != nil || value.pointer {
				return false, nil // The shared machine reader reports invalid inputs.
			}
			if pointer && !value.opaque {
				var valid bool
				origin, valid = shift(origin, form.source, subtract)
				if !valid {
					return fail()
				}
				if carry {
					origin.address = x86StaticSBAddress{} // Defined CF need not be constant.
				}
				return write(form.destination, origin, form.spec.flagsKilled, form.spec.flagsDefined)
			}
			if !subtract && value.opaque && !pointer && fixedLocalNumericRead(form.destination, 8, state) {
				sourceOrigin, valid := shift(value.identity, form.destination, false)
				if !valid {
					return fail()
				}
				if carry {
					sourceOrigin.address = x86StaticSBAddress{}
				}
				return write(form.destination, sourceOrigin, form.spec.flagsKilled, form.spec.flagsDefined)
			}
			return false, nil // Other arithmetic results are bits, not addresses.
		case "INC", "DEC":
			if pointer {
				var valid bool
				origin, valid = shift(origin, Operand{Kind: OpImm, Imm: 1}, form.spec.stem == "DEC")
				if !valid {
					return fail()
				}
				return write(form.destination, origin, form.spec.flagsKilled, form.spec.flagsDefined)
			}
		}
	}
	if effect, known, err := x86NamedLEAByteEffect(ins.Op, *ins, "amd64"); known && err == nil && x86LEAWidth(ins.Op, "amd64") == 8 {
		memory := ins.Args[0].Mem
		origin, pointer := state.opaque[memory.Base]
		if pointer && origin.valid() {
			for _, input := range effect.operands {
				if input.read && input.operand.Reg != memory.Base && !fixedLocalNumericRead(input.operand, input.width, state) {
					return fail()
				}
			}
			// An aliased pointer index is still a second pointer, even if it
			// happens to share the base's spelling or original entry slot.
			if _, secondPointer := state.opaque[memory.Index]; secondPointer {
				return fail()
			}
			displacement, known, valid := fixedLocalNativeDisplacement(memory, state)
			if !valid || !fixedLocalOriginOwners(origin, proof) {
				return fail()
			}
			if origin.address.symbol != "" {
				if known {
					origin.address.offset += displacement
				} else {
					origin.address = x86StaticSBAddress{}
				}
			}
			return write(ins.Args[1], origin, effect.flagsKilled, effect.flagsDefined)
		}
	}
	form, known, err := x86ScalarCompareProperties(ins.Op, *ins, "amd64")
	if !known || err != nil || form.test || form.bits != 64 {
		return false, nil
	}
	values := [2]x86FixedLocalOrigins{}
	opaque := func(index int) bool {
		operand := form.args[index]
		if origin, found := fixedLocalOpaqueRegister(operand, state); found {
			values[index] = origin
			return true
		}
		if operand.Kind != OpMem || proof == nil {
			return false
		}
		address, err := fixedLocalMemoryAddress(*ins, index, proof.frame)
		if err != nil {
			return false
		}
		offset, found := fixedLocalPrivateOffset(address, state)
		if !found {
			return false
		}
		origin, found := state.opaqueCells[offset]
		values[index] = origin
		return found && origin.valid()
	}
	pointers := [2]bool{opaque(0), opaque(1)}
	if !pointers[0] || !pointers[1] {
		return false, nil
	}
	for index, operand := range form.args {
		if !fixedLocalOriginOwners(values[index], proof) {
			return fail()
		}
		if operand.Kind == OpMem {
			if _, err := fixedLocalMemory(ins, index, state, proof, residue, 8, 1, false, true); err != nil {
				return true, err
			}
		}
	}
	flags := uint8(x86ByteFlagsAll)
	comparison := x86FixedLocalComparison{}
	if values[0].hasLiteral() || values[1].hasLiteral() {
		if !pointers[0] || !pointers[1] || !fixedLocalOriginOwners(values[0], proof) || !fixedLocalOriginOwners(values[1], proof) {
			return fail()
		}
		// The actual CMP preserves every architectural flag. Its optional
		// literal equality fact is narrower than that emitted operation.
		for index, value := range values {
			if literal, single := value.literal(); single && form.args[1-index].Kind == OpReg {
				comparison = x86FixedLocalComparison{register: form.args[1-index].Reg, literal: literal}
				break
			}
		}
	}
	state.flags, state.comparison = flags, comparison
	return true, nil
}

func fixedLocalOpaqueRegister(operand Operand, state *x86FixedLocalState) (x86FixedLocalOrigins, bool) {
	root, valid := x86CallerGP(operand.Reg)
	if operand.Kind != OpReg || !valid || root != operand.Reg {
		return x86FixedLocalOrigins{}, false
	}
	origin, found := state.opaque[root]
	return origin, found && origin.valid()
}

// Native effective addresses use wrapping machine arithmetic, unlike relocated
// private-frame offsets. A complete NUM index needs no caller bounds proof.
func fixedLocalNativeDisplacement(memory MemRef, state *x86FixedLocalState) (offset int64, known, valid bool) {
	if memory.OffRaw != "" || memory.Sym != "" || memory.Segment != "" || memory.IndexExt != "" {
		return 0, false, false
	}
	if memory.Index == "" {
		return memory.Off, true, memory.Scale == 0
	}
	if !fixedLocalNumericRead(Operand{Kind: OpReg, Reg: memory.Index}, 8, state) ||
		memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
		return 0, false, false
	}
	index, known := state.constants[memory.Index]
	return memory.Off + index*memory.Scale, known, true
}

func intersectFixedLocalOrigins[K, V comparable](previous, current map[K]V) bool {
	changed := false
	for key, value := range previous {
		if incoming, found := current[key]; !found || incoming != value {
			delete(previous, key)
			changed = true
		}
	}
	return changed
}
