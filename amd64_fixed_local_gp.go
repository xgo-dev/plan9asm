package plan9asm

// Reuse the ordinary typed GP grammar. The descriptor only names byte and
// FLAGS dependencies; this consumer must still establish every private read,
// address origin and write. CMP/TEST retain their opposite immediate roles.
func fixedLocalGPByteEffect(ins Instr) (x86TypedByteEffect, bool, error) {
	if effect, known, err := x86NamedLEAByteEffect(ins.Op, ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedGPByteEffect(ins.Op, ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedImplicitMultiplyByteEffect(ins.Op, ins, "amd64"); known {
		return effect, true, err
	}
	form, known, err := x86ScalarCompareProperties(ins.Op, ins, "amd64")
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{flagsDefined: x86ByteFlagsAll, flagsKilled: x86ByteFlagsAll}
	if form.test {
		effect.flagsDefined &^= x86ByteFlagAF
	}
	for index, operand := range form.args {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: index, operand: operand, width: int64(form.bits / 8), read: true,
		})
	}
	return effect, true, nil
}

// Preserve a full numerical word only after the ordinary typed transfer has
// succeeded. These are machine-word values with wraparound, not checked pointer
// offsets or termination facts. The existing family owns grammar and immediates;
// partial writes and numerical values depending on unknown carry stay unknown.
func fixedLocalConstantArithmetic(ins Instr, effect x86TypedByteEffect, state *x86FixedLocalState) (Reg, int64, bool) {
	spec, recognized := x86LockScalarRMWSpecs[ins.Op]
	if !recognized || spec.bits != 64 || len(effect.operands) == 0 {
		return "", 0, false
	}
	destination := effect.operands[len(effect.operands)-1]
	root, valid := x86CallerGP(destination.operand.Reg)
	old, known := state.constants[root]
	if destination.operand.Kind != OpReg || destination.width != 8 || !destination.write ||
		!valid || root != destination.operand.Reg || root == SP ||
		!known && spec.stem != "XOR" {
		return "", 0, false
	}
	// The shared typed family already resolved aliases and encoded immediates.
	// Its input-free XOR descriptor is the existing self-XOR zero rule.
	if spec.stem == "XOR" && !effect.operands[0].read && !destination.read {
		return root, 0, true
	}
	if !known || !fixedLocalNumericRead(destination.operand, 8, state) {
		return "", 0, false
	}
	value, input := uint64(old), uint64(0)
	if !spec.unary {
		operand := effect.operands[0].operand
		source, constant := operand.Imm, operand.Kind == OpImm
		if operand.Kind == OpReg {
			source, constant = state.constants[operand.Reg]
		}
		if !constant || !fixedLocalNumericRead(operand, 8, state) {
			return "", 0, false
		}
		input = uint64(source)
	}
	switch spec.stem {
	case "ADD":
		value += input
	case "SUB":
		value -= input
	case "AND":
		value &= input
	case "OR":
		value |= input
	case "XOR":
		value ^= input
	case "INC":
		value++
	case "DEC":
		value--
	case "NEG":
		value = -value
	case "NOT":
		value = ^value
	default:
		return "", 0, false
	}
	return root, int64(value), true
}

// A parsed address is not necessarily a memory access. Numerical LEA and
// sized NOP use the same syntax without loading/storing it. Query the validated
// effect rather than granting them a fabricated private-storage certificate.
func fixedLocalGPAddressOnly(ins Instr, index int) bool {
	if index < 0 || index >= len(ins.Args) || ins.Args[index].Kind != OpMem {
		return false
	}
	effect, known, err := fixedLocalGPByteEffect(ins)
	if !known || err != nil || effect.dynamicMemory {
		return false
	}
	for _, operand := range effect.operands {
		if operand.index == index && (operand.operand.Kind == OpMem || operand.operand.Kind == OpSym) &&
			(operand.read || operand.write) {
			return false
		}
	}
	return true
}

func fixedLocalTypedByteStep(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int,
	effect x86TypedByteEffect) error {
	fail := func() error {
		return goAMD64FrameContext("fixed local typed effect lacks numerical bytes, FLAGS or private storage: %s", ins.Op)
	}
	if effect.dynamicMemory || state.flags&effect.flagsRead != effect.flagsRead {
		return fail()
	}
	alignment := int64(1)
	if effect.vector.upperWrite != x86TypedVectorUpperUnknown {
		if effect.vector.upperWrite != x86TypedVectorUpperPreserve && effect.vector.upperWrite != x86TypedVectorUpperZero ||
			effect.vector.memoryAlignment <= 0 {
			return fail()
		}
		alignment = effect.vector.memoryAlignment
	}
	// Read all inputs before any write, including aliased outputs. RMW receives
	// one write-capable access certificate only after its old bytes are proved.
	for _, operand := range effect.operands {
		if operand.requiredBytes != 0 && (!operand.read || operand.operand.Kind != OpReg ||
			amd64VectorByteWidth(operand.operand.Reg) == 0 ||
			operand.requiredBytes&^x86CallerVectorByteMask(operand.width) != 0) {
			return fail()
		}
		if !operand.read {
			continue
		}
		if operand.operand.Kind != OpMem && operand.operand.Kind != OpSym {
			if operand.operand.Kind == OpReg && amd64VectorByteWidth(operand.operand.Reg) != 0 {
				mask := x86CallerVectorByteMask(operand.width)
				if operand.requiredBytes != 0 {
					mask = operand.requiredBytes
				}
				if effect.vector.upperWrite == x86TypedVectorUpperUnknown || mask == 0 ||
					state.vectors[x86CallerVectorRoot(operand.operand.Reg)]&mask != mask {
					return fail()
				}
				continue
			}
			if !fixedLocalMachineRead(ins, operand, state, sig, proof, residue) {
				return fail()
			}
			continue
		}
		if err := fixedLocalMachineMemory(ins, operand, state, proof, residue, alignment); err != nil {
			return err
		}
	}
	for _, operand := range effect.operands {
		if !operand.write {
			continue
		}
		switch operand.operand.Kind {
		case OpMem:
			offset, role, err := fixedLocalMemoryAccess(ins, operand.index, state, proof, residue, operand.width, alignment, true, false)
			if err != nil {
				return err
			}
			if role == x86FixedLocalPrivateMemory {
				// An integer RMW drops an overlapping native-address role,
				// but its untouched actual machine bytes remain initialized.
				for start := offset - 7; start < offset+operand.width; start++ {
					origin, found := state.opaqueCells[start]
					if found && fixedLocalOriginOwners(origin, proof) {
						if start < 0 || start > proof.frame-8 {
							return fail()
						}
						state.bytes.setRange(start, 8, true)
					}
				}
				fixedLocalNumericalStore(state, offset, operand.width, true)
			}
		case OpReg:
			if amd64VectorByteWidth(operand.operand.Reg) != 0 {
				mask := x86CallerVectorByteMask(operand.width)
				if effect.vector.upperWrite == x86TypedVectorUpperUnknown || mask == 0 {
					return fail()
				}
				root := x86CallerVectorRoot(operand.operand.Reg)
				if effect.vector.upperWrite == x86TypedVectorUpperZero {
					state.vectors[root] = ^uint64(0)
				} else {
					state.vectors[root] |= mask
				}
				continue
			}
			root, valid := x86CallerGP(operand.operand.Reg)
			mask := x86CallerByteMask(operand.operand.Reg, operand.width)
			_, private := state.pointers[root]
			origin, opaque := state.opaque[root]
			if !valid || root == SP || mask == 0 ||
				private && operand.width != 8 {
				return fail()
			}
			if opaque && fixedLocalOriginOwners(origin, proof) {
				state.known[root] = 255 // Narrow writes preserve defined native upper bits.
			}
			if operand.width == 4 {
				mask = 255 // Architectural dword writes define the upper half.
			}
			delete(state.pointers, root)
			delete(state.opaque, root)
			delete(state.constants, root)
			fixedLocalWriteBooleans(state, operand.operand.Reg, operand.width, 0)
			state.known[root] |= mask
		default:
			return fail() // FP transport and external stores have separate owners.
		}
	}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	if effect.flagsKilled|effect.flagsDefined != 0 {
		state.comparison = x86FixedLocalComparison{}
	}
	return nil
}

// Integer effects consume machine bits. Native addresses have all eight bytes;
// relocated private-frame identities do not. This does not change the stricter
// address-index, scalar transport or result-ABI predicates.
func fixedLocalMachineRead(ins *Instr, operand x86TypedByteOperand, state *x86FixedLocalState,
	sig FuncSig, proof *x86FixedLocalProof, residue int) bool {
	if amd64IsKOperand(operand.operand) {
		return operand.width == 8 && state.masks[operand.operand.Reg]
	}
	if operand.operand.Kind == OpFP {
		value, err := fixedLocalReadValue(ins, operand.index, state, sig, proof, residue, operand.width, false)
		return err == nil && !value.pointer && (!value.opaque || fixedLocalOriginOwners(value.identity, proof))
	}
	if fixedLocalNumericRead(operand.operand, operand.width, state) {
		return true
	}
	root, valid := x86CallerGP(operand.operand.Reg)
	origin, native := state.opaque[root]
	_, private := state.pointers[root]
	return operand.operand.Kind == OpReg && valid && root != SP && !private && native &&
		x86CallerByteMask(operand.operand.Reg, operand.width) != 0 && fixedLocalOriginOwners(origin, proof)
}

func fixedLocalMachineMemory(ins *Instr, operand x86TypedByteOperand, state *x86FixedLocalState,
	proof *x86FixedLocalProof, residue int, alignment int64) error {
	if operand.operand.Kind == OpSym {
		_, _, err := fixedLocalReadMemory(ins, operand.index, state, proof, residue, operand.width, alignment)
		return err
	}
	address, err := fixedLocalMemoryAddress(*ins, operand.index, proof.frame)
	if err != nil {
		return err
	}
	offset, private := fixedLocalPrivateOffset(address, state)
	if !private {
		_, _, err := fixedLocalMemoryAccess(ins, operand.index, state, proof, residue, operand.width, alignment, operand.write, false)
		return err
	}
	if _, err := fixedLocalMemory(ins, operand.index, state, proof, residue, operand.width, alignment, operand.write, true); err != nil {
		return err
	}
	for index := offset; index < offset+operand.width; index++ {
		if state.bytes.has(index) {
			continue
		}
		defined := false
		// Full pointer spills need not be aligned. Exactly eight possible
		// starting offsets can contain a byte, independent of frame size.
		for start := index - 7; start <= index; start++ {
			origin, found := state.opaqueCells[start]
			if found && start >= 0 && start <= proof.frame-8 && fixedLocalOriginOwners(origin, proof) {
				defined = true
				break
			}
		}
		if !defined {
			return goAMD64FrameContext("fixed local machine read contains undefined or relocated private bytes")
		}
	}
	return nil
}
