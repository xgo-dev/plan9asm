package plan9asm

// A logical declared-field address is neither an incoming/native pointer nor
// numerical bits. The field and its interior offset belong to this root's
// actual scalar ABI0 layout; another root sharing a helper supplies nothing.
type x86ResultSlotAddress struct {
	start, end, offset int64
	valid              bool
}

func x86DirectTailResultAddressTransfer(ins Instr, state *x86ResultState, owned []bool, resultOffset int64,
	arch string, transfer x86ResultSourceTransfer, ordinal int) bool {
	if len(state.resultAddressSlots) == 0 {
		return transfer(ordinal, ins, state, owned, resultOffset, arch)
	}
	form := x86SourceMoveInstruction(ins, arch) // Dispatch copy, never source identity.
	word := x86ResultPointerWord(arch)
	move, lea := Op("MOVQ"), Op("LEAQ")
	if arch == "386" {
		move, lea = "MOVL", "LEAL"
	}
	address := func(arg Operand) x86ResultSlotAddress {
		if arg.Kind == OpReg {
			index, _, ok := x86ResultGP(arg.Reg, word, arch)
			if ok {
				return state.resultAddressGP[index]
			}
		}
		return x86ResultSlotAddress{}
	}
	writeAddress := func(destination Operand, value x86ResultSlotAddress) bool {
		if destination.Kind != OpReg {
			return false
		}
		index, _, ok := x86ResultGP(destination.Reg, word, arch)
		if !ok || !value.valid || arch == "amd64" && index == 14 {
			return false
		}
		state.resultAddressGP[index] = value
		state.gp[index], state.canonicalGP[index] = 0, 0
		state.pointerGP[index], state.callerAddressGP[index] = false, false
		return true
	}
	if len(form.Args) == 2 {
		first, last := form.Args[0], form.Args[1]
		if form.Op == lea && first.Kind == OpFP {
			if width, err := x86LEAOperandWidth(form, arch); err != nil || width != word {
				return false
			}
			for _, slot := range state.resultAddressSlots {
				if first.FPOffset >= slot.start && first.FPOffset < slot.end {
					slot.offset = first.FPOffset
					return writeAddress(last, slot)
				}
			}
			return false // Parameters, padding and neighboring fields are not results.
		}
		if form.Op == move {
			if value := address(first); value.valid {
				return writeAddress(last, value)
			}
		}
		if form.Op == lea && first.Kind == OpMem {
			memory := first.Mem
			if value := address(Operand{Kind: OpReg, Reg: memory.Base}); value.valid {
				if _, err := x86LEAOperandWidth(form, arch); err != nil || !x86ResultSlotMemory(memory) ||
					memory.Off < value.start-value.offset || memory.Off >= value.end-value.offset {
					return false
				}
				value.offset += memory.Off
				return writeAddress(last, value)
			}
		}
	}

	// Only registered scalar effects consume these logical bytes. The
	// actual lowerer still emits the original source memory operand against
	// boundFPAddress's real logical backing. No native-memory certificate follows.
	local := ins
	local.Args = append([]Operand(nil), ins.Args...)
	usesSlot, writesSlot := false, false
	for index, arg := range form.Args {
		if arg.Kind != OpMem {
			continue
		}
		value := address(Operand{Kind: OpReg, Reg: arg.Mem.Base})
		if !value.valid && !state.shapeOnly {
			continue
		}
		width := x86ResultSlotMoveBytes(form, arch)
		if width == 0 || len(form.Args) != 2 || !x86ResultSlotMemory(arg.Mem) {
			if value.valid {
				return false
			}
			continue
		}
		if state.shapeOnly && !value.valid {
			// Shape validation has no reaching alias. Its representative checks
			// only the complete scalar form; the fixed point repeats exact field,
			// offset, initialized bytes and alias checks on every reachable path.
			for _, slot := range state.resultAddressSlots {
				if slot.end-slot.start >= width {
					value = slot
					value.offset = slot.start
					break
				}
			}
		} else if arg.Mem.Off >= value.start-value.offset && arg.Mem.Off <= value.end-value.offset-width {
			value.offset += arg.Mem.Off
		} else {
			return false
		}
		if !value.valid {
			return false
		}
		local.Args[index] = Operand{Kind: OpFP, FPOffset: value.offset}
		usesSlot, writesSlot = true, writesSlot || index == 1
	}
	if usesSlot {
		before := state.resultAddressGP
		writeBoundary := resultOffset
		if state.logicalFrameParameters {
			writeBoundary = 0 // Only independently owned numeric bytes in private parameter copies.
		}
		if !transfer(ordinal, local, state, owned, writeBoundary, arch) {
			return false
		}
		x86ResultSlotRevokeOverwrites(local, state, before, arch)
		state.resultAddressWritten = state.resultAddressWritten || writesSlot
		return true
	}
	for index, arg := range form.Args {
		if arg.Kind == OpMem {
			if address(Operand{Kind: OpReg, Reg: arg.Mem.Index}).valid {
				return false
			}
			if state.resultAddressWritten && arg.Mem.Sym == "" && form.Op != lea && !x86DirectTailPCBranch(form) {
				return false // Fresh logical backing cannot hide a native alias read.
			}
		}
		if value := address(arg); value.valid && !x86ResultSlotOverwrite(form, index, arch) {
			return false // No comparison, numerical/vector transport or escape.
		}
	}
	before := state.resultAddressGP
	if !transfer(ordinal, ins, state, owned, resultOffset, arch) {
		return false
	}
	x86ResultSlotRevokeOverwrites(ins, state, before, arch)
	for index, arg := range form.Args {
		if arg.Kind == OpFP && arg.FPOffset >= resultOffset {
			state.resultAddressWritten = state.resultAddressWritten || x86ResultSlotDirectWrite(form, index, arch)
		}
	}
	return true
}

func x86ResultSlotMoveBytes(ins Instr, arch string) int64 {
	if form, known, err := x86SqrtProperties(ins, arch); known {
		if err != nil || !form.legacy || !form.scalar || form.memory != 0 {
			return 0
		}
		return int64(form.bits / 8) // Read-only scalar SQRT uses the same exact logical field.
	}
	if form, known, err := x86GPSIMDTransferProperties(ins, arch); known {
		if err != nil || form.mmx || form.spec.rawOnly || form.memory < 0 {
			return 0
		}
		return int64(form.bits / 8) // Mode32 Q memory/X copies really are 8 bytes.
	}
	if form, known, err := amd64ScalarVectorMoveProperties(ins, arch); known {
		if err != nil || !form.spec.legacy || form.mask >= 0 || form.memory < 0 {
			return 0
		}
		return int64(form.spec.bits / 8)
	}
	width := x86RawReturnScalarMoveBytes(ins.Op)
	if width == 8 && arch == "386" {
		return 0 // Only the typed X/m64 branch above has a mode32 qword role.
	}
	return width
}

func x86ResultSlotDirectWrite(ins Instr, index int, arch string) bool {
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		for _, operand := range effect.operands {
			if operand.index == index && operand.write {
				return true
			}
		}
	}
	_, write, known := x86InstructionMemoryShape(ins, index, arch)
	return known && write
}

func x86ResultSlotRevokeOverwrites(ins Instr, state *x86ResultState, before [16]x86ResultSlotAddress, arch string) {
	var live [16]bool
	for index, value := range before {
		live[index] = value.valid
	}
	live = x86ResultCallerAddressesAfter(ins, live, nil, arch)
	for index := range before {
		if !live[index] {
			state.resultAddressGP[index] = x86ResultSlotAddress{}
		}
	}
}

func x86ResultSlotMemory(memory MemRef) bool {
	return memory.Sym == "" && memory.OffRaw == "" && memory.Index == "" && memory.Scale == 0 &&
		memory.Segment == "" && memory.IndexExt == "" && memory.Off == int64(int32(memory.Off))
}

func x86ResultSlotOverwrite(ins Instr, index int, arch string) bool {
	if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil {
		for _, operand := range effect.operands {
			if operand.index == index {
				return operand.write && !operand.read
			}
		}
	}
	return len(ins.Args) == 2 && index == 1 && x86RawReturnScalarMoveBytes(ins.Op) != 0
}
