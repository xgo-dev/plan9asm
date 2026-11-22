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
	if effect, known, err := x86TypedAccumulatorSignExtendByteEffect(ins.Op, ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedScalarFloatIntegerByteEffect(ins.Op, ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedCRC32ByteEffect(ins.Op, ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedBitScanByteEffect(ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedSegmentQueryByteEffect(ins.Op, ins, "amd64"); known {
		if len(effect.operands) == 2 {
			// LAR and LSL tie the native result to its entire prior word.
			// A failed query can retain even the upper half of a dword result.
			effect.operands[1].width = 8
		}
		return effect, true, err
	}
	if effect, known, err := x86TypedExchangeAddByteEffect(ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedCompareExchangeByteEffect(ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedCacheLineWritebackByteEffect(ins, "amd64"); known {
		return effect, true, err
	}
	if effect, known, err := x86TypedMXCSRByteEffect(ins.Op, ins, "amd64"); known {
		return effect, true, err
	}
	if form, known, err := x86MOVNTIProperties(ins.Op, ins, "amd64"); known {
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		if form.destination.Kind != OpMem {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("fixed local MOVNTI requires a native memory destination")
		}
		width := int64(form.bits / 8)
		return x86TypedByteEffect{operands: []x86TypedByteOperand{
			{index: 0, operand: form.source, width: width, read: true},
			{index: 1, operand: form.destination, width: width, write: true},
		}}, true, nil
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

func fixedLocalGPFootprintSupported(ins Instr, effect x86TypedByteEffect) bool {
	if !effect.dynamicMemory {
		return true
	}
	_, _, bitString := amd64BitTestProperties(string(ins.Op))
	return bitString && len(ins.Args) == 2 && ins.Args[1].Kind == OpMem && x86ResultNamedPredicateInstruction(ins)
}

func fixedLocalTypedByteStep(ins *Instr, state *x86FixedLocalState, sig FuncSig, proof *x86FixedLocalProof, residue int,
	effect x86TypedByteEffect) error {
	fail := func() error {
		return goAMD64FrameContext("fixed local typed effect lacks numerical bytes, FLAGS or private storage: %s", ins.Op)
	}
	if state.flags&effect.flagsRead != effect.flagsRead || !fixedLocalGPFootprintSupported(*ins, effect) {
		return fail()
	}
	if effect.dynamicMemory {
		if err := fixedLocalRegisterBitStringStep(ins, state, proof, residue, effect.operands[0], effect.operands[1]); err != nil {
			return err
		}
		fixedLocalApplyFlags(state, effect)
		return nil
	}

	alignment := int64(1)
	upper := effect.vector.upperWrite
	switch upper {
	case x86TypedVectorUpperUnknown:
	case x86TypedVectorUpperPreserve, x86TypedVectorUpperZero, x86TypedVectorNoWrite:
		if effect.vector.memoryAlignment <= 0 {
			return fail()
		}
		alignment = effect.vector.memoryAlignment
	default:
		return fail()
	}
	// Read all inputs before any write, including aliased outputs. RMW receives
	// one write-capable access certificate only after its old bytes are proved.
	for _, operand := range effect.operands {
		vector := operand.operand.Kind == OpReg && amd64VectorByteWidth(operand.operand.Reg) != 0
		if operand.requiredBytes != 0 && (!operand.read || !vector ||
			operand.requiredBytes&^x86CallerVectorByteMask(operand.width) != 0) ||
			operand.preservedBytes != 0 && (!operand.write || !vector ||
				operand.preservedBytes&^x86CallerVectorByteMask(operand.width) != 0) {
			return fail()
		}
		if !operand.read {
			continue
		}
		if operand.operand.Kind != OpMem && operand.operand.Kind != OpSym {
			if vector {
				mask := x86CallerVectorByteMask(operand.width)
				if operand.requiredBytes != 0 {
					mask = operand.requiredBytes
				}
				if upper == x86TypedVectorUpperUnknown || mask == 0 ||
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
		if err := fixedLocalMachineMemory(ins, operand, state, proof, residue, operand.memoryAlignment(alignment)); err != nil {
			return err
		}
	}
	for _, operand := range effect.operands {
		if !operand.write {
			continue
		}
		switch operand.operand.Kind {
		case OpMem:
			offset, role, err := fixedLocalMemoryAccess(ins, operand.index, state, proof, residue, operand.width,
				operand.memoryAlignment(alignment), true, false)
			if err != nil {
				return err
			}
			if role == x86FixedLocalPrivateMemory {
				if operand.partialWrite {
					fixedLocalNumericalStore(state, offset, operand.width, false)
					continue
				}
				if err := fixedLocalMachineBytesStore(state, proof, offset, operand.width); err != nil {
					return err
				}
			}
		case OpReg:
			if amd64IsKOperand(operand.operand) {
				if operand.width != 8 || upper != x86TypedVectorNoWrite {
					return fail()
				}
				state.masks[operand.operand.Reg] = true
				continue
			}
			if amd64VectorByteWidth(operand.operand.Reg) != 0 {
				mask := x86CallerVectorByteMask(operand.width)
				if upper != x86TypedVectorUpperPreserve && upper != x86TypedVectorUpperZero || mask == 0 {
					return fail()
				}
				root := x86CallerVectorRoot(operand.operand.Reg)
				known := state.vectors[root] | (mask &^ operand.preservedBytes)
				if upper == x86TypedVectorUpperZero {
					known |= ^mask
				}
				state.setVectorBytes(root, known)
				if state.vectorLiterals != nil {
					state.observeVectorZero(*ins, root, upper)
				}
				continue
			}
			root, valid := x86CallerGP(operand.operand.Reg)
			mask := x86CallerByteMask(operand.operand.Reg, operand.width)
			_, private := state.pointers[root]
			origin, opaque := state.opaque[root]
			stackValue := root == SP && operand.stackValue && (operand.width == 4 || operand.width == 8)
			if !valid || mask == 0 || root == SP && !stackValue ||
				private && operand.width != 8 && !stackValue {
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
	fixedLocalApplyFlags(state, effect)
	return nil
}

func fixedLocalApplyFlags(state *x86FixedLocalState, effect x86TypedByteEffect) {
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	if effect.flagsKilled|effect.flagsDefined != 0 {
		state.comparison = x86FixedLocalComparison{}
	}
}

// Integer effects consume machine bits. Native addresses have all eight bytes;
// relocated private-frame identities do not. This does not change the stricter
// address-index, scalar transport or result-ABI predicates.
func fixedLocalMachineRead(ins *Instr, operand x86TypedByteOperand, state *x86FixedLocalState,
	sig FuncSig, proof *x86FixedLocalProof, residue int) bool {
	if operand.numericalGP {
		return fixedLocalNumericRead(operand.operand, operand.width, state)
	}
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
	if operand.addressOnly {
		return nil // The recorded access does not establish any numerical bytes.
	}
	return fixedLocalMachineBytesRead(state, proof, offset, operand.width)
}

func fixedLocalMachineBytesRead(state *x86FixedLocalState, proof *x86FixedLocalProof, offset, width int64) error {
	for index := offset; index < offset+width; index++ {
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

func fixedLocalMachineBytesStore(state *x86FixedLocalState, proof *x86FixedLocalProof, offset, width int64) error {
	// A numerical write drops any overlapping native-address role.
	// Preserve the initialized machine bytes outside the written span.
	for start := offset - 7; start < offset+width; start++ {
		origin, found := state.opaqueCells[start]
		if found && fixedLocalOriginOwners(origin, proof) {
			if start < 0 || start > proof.frame-8 {
				return goAMD64FrameContext("fixed local native address spill crosses storage")
			}
			state.bytes.setRange(start, 8, true)
		}
	}
	fixedLocalNumericalStore(state, offset, width, true)
	return nil
}
