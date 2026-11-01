package plan9asm

func x86RawIFMASource(ins Instr, arch string) bool {
	_, known, err := x86IFMAProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86ResultIFMAStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86IFMAProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	return x86IFMAResultTransfer(ins, form, state, owned, arch, false), true
}

func x86LoweredIFMAStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86IFMAProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawIFMASource(ins, arch) {
			return false, true
		}
		// Keep the independently validated physical form. Clearing local
		// provenance must not reparse it under a named mode32 operand cap.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86IFMAResultTransfer(ins, form, state, owned, arch, true), true
}

func x86IFMAResultTransfer(ins Instr, form x86IFMAForm, state *x86ResultState, owned []bool, arch string, native bool) bool {
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false
		}
	}
	first := ins.Args[form.first]
	var input uint64
	if first.Kind == OpReg {
		index, _ := amd64VectorRegisterIndex(first.Reg, form.byteWidth)
		input = state.vectorBytes(index)
	} else {
		if !x86ResultReadWithNativeContinuation(ins, first, int64(form.memoryBytes), state, owned, arch, native) {
			return false
		}
		input = ^uint64(0) // Conditional numerical bytes, never a reusable backing fact.
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	other, old := state.vectorBytes(second), state.vectorBytes(destination)
	var defined uint64
	for offset := 0; offset < form.byteWidth; offset += 8 {
		// Bits 51:0 require seven source bytes, not irrelevant byte7. The
		// complete eight-byte accumulator is data even with EVEX.z.
		firstMask := uint64(0x7f) << uint(offset)
		if form.broadcast {
			firstMask = 0x7f
		}
		otherMask, output := uint64(0x7f)<<uint(offset), uint64(0xff)<<uint(offset)
		if input&firstMask == firstMask && other&otherMask == otherMask && old&output == output {
			defined |= output
		}
	}
	state.writeVector(destination, form.byteWidth, defined, false)
	return true // Unknown register results remain unknown; FLAGS and pointer roles are unchanged.
}
