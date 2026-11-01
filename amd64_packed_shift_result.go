package plan9asm

// One output byte can span two input bytes for an immediate bit shift. With an
// initialized but unknown count, it instead requires the union of every input
// bit that could reach it. Oversized logical counts contribute only zeros.
// The masks describe numerical dependence, never the native memory envelope.
func x86PackedShiftByteInputs(form x86PackedShiftForm, output int) (data, count uint64) {
	laneBytes := form.laneBits / 8
	if form.countMode == x86PackedShiftBytes {
		laneBytes = 16
	}
	lane, at := output/laneBytes*laneBytes, output%laneBytes
	first, last := at*8, at*8+7
	if form.countOperand.Kind == OpImm {
		shift := int(uint8(form.countOperand.Imm))
		if form.countMode == x86PackedShiftBytes {
			shift *= 8
		}
		if form.left {
			first, last = first-shift, last-shift
		} else {
			first, last = first+shift, last+shift
		}
	} else {
		if form.left {
			first = 0
		} else {
			last = laneBytes*8 - 1
		}
		count = 255 // The upper qword of a uniform register count is ignored.
		if form.countMode == x86PackedShiftPerLane {
			count = x86CallerVectorByteMask(int64(laneBytes)) << uint(lane)
		}
	}
	if first < 0 {
		first = 0
	}
	if form.arithmetic && first >= laneBytes*8 {
		first = laneBytes*8 - 1 // Every shifted-out bit reads the sign bit.
	}
	if last >= laneBytes*8 {
		last = laneBytes*8 - 1
	}
	if first <= last {
		data = x86CallerVectorByteMask(int64(last/8-first/8+1)) << uint(lane+first/8)
	}
	return data, count
}

func x86PackedShiftDefinedBytes(form x86PackedShiftForm, data, counts, old uint64) uint64 {
	var known uint64
	for output := 0; output < form.byteWidth; output++ {
		dataMask, countMask := x86PackedShiftByteInputs(form, output)
		if data&dataMask == dataMask && counts&countMask == countMask {
			known |= uint64(1) << uint(output)
		}
	}
	// A defined mask is not a known active mask. Every inactive merging byte
	// still needs its old destination; inactive zeroing bytes are constants.
	if form.mask >= 0 && !form.zeroing {
		known &= old
	}
	return known
}

func x86ResultPackedShiftStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultPackedShiftStepWithRead(ins, state, owned, arch, false)
}

func x86ResultPackedShiftStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	literal := x86RawByteShiftLiteralForm(ins, arch)
	if err != nil || form.mmx || !literal && (!x86ResultNamedPredicateInstruction(ins) ||
		ins.x86PackedShiftEncoding != x86RawPackedShiftAbsent || ins.x86PackedShiftW) {
		return false, true // Raw identity and physical MMX have separate owners.
	}
	// This is the existing independent same-source DATA role, not ordinary
	// native continuation. Its full tuple still needs loweredStaticReads;
	// leaving the raw origin intact prevents an incoming-pointer fallback.
	var pending x86ResultShiftBits
	if nativeRead && ins.Args[form.data].Kind == OpReg {
		input, _ := amd64VectorRegisterIndex(ins.Args[form.data].Reg, form.byteWidth)
		destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
		pending = x86ResultShiftBitSource(ins, form, state.vectorBytes(input), destination)
	}
	if !x86ResultPackedShiftInputs(ins, form, state, owned, arch, nativeRead) {
		return false, true
	}
	if nativeRead {
		// Record only at the original named entry. The raw consumer shares
		// byte effects through a local projection, not this named-only fact.
		state.shiftBits = pending
	}
	return true, true
}

func x86ResultPackedShiftInputs(ins Instr, form x86PackedShiftForm, state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	if form.memory >= 0 {
		// Even a saturating count or zero mask cannot create memory authority.
		// Legacy m128 counts additionally need original native backing. Only
		// lowering's ephemeral same-file DATA directory can provide an SB
		// input here; logical FP/AUTO storage still cannot stand in for it.
		memory := ins.Args[form.memory]
		if _, static := x86StaticSBReadAddress(memory, arch); form.legacy && !static &&
			(!nativeRead || !x86OrdinaryNativeMemoryOperand(memory, arch)) {
			return false
		}
		if !x86ResultReadWithNativeContinuation(ins, memory, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false
		}
	}
	bytes := func(index int) uint64 {
		if index == form.memory {
			return x86CallerVectorByteMask(int64(form.byteWidth))
		}
		operand := ins.Args[index]
		register, _ := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
		return state.vectorBytes(register)
	}
	data, counts := bytes(form.data), ^uint64(0)
	if form.countOperand.Kind != OpImm {
		counts = bytes(form.count)
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth,
		x86PackedShiftDefinedBytes(form, data, counts, state.vectorBytes(destination)), form.legacy)
	return true
}
