package plan9asm

func x86RawCompactSource(ins Instr, arch string) bool {
	form, known, err := x86PackedCompactProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86RawOrdinaryVectorSource(ins, arch) {
		return false
	}
	// Compression's memory is its destination, not the first data operand.
	// Check that role as well: exact bytes grant neither RIP/static backing
	// nor a segment, frame or nondefault-address continuation.
	return form.memory < 0 || x86RawOrdinaryVectorSourceAt(ins, arch, form.memory)
}

// Unknown mask values can select any source lane and any merge byte. Require
// the complete source and, for merging, the complete old destination. A mask's
// definedness is not a constant-value or memory-access certificate.
func x86ResultCompactExpandStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	return x86ResultCompactExpandMemoryStep(ins, state, owned, resultOffset, arch, false)
}

func x86ResultCompactExpandMemoryStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string, pairedNative bool) (bool, bool) {
	form, known, err := x86PackedCompactProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil || form.undefinedOpcode() {
		return false, true
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !pairedNative || !x86RawCompactSource(ins, arch) {
			return false, true
		}
		// Consume only this instruction's exact original identity. Preserve
		// the validated physical form; no standalone query gains this view.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	for index, operand := range ins.Args {
		if operand.Kind != OpReg || index == form.mask {
			continue
		}
		register, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		if !valid || arch == "386" && register >= 8 {
			return false, true // Accepted high-bank syntax is not a physical mode32 value input.
		}
		if index == 0 || form.mask >= 0 && !form.zeroing {
			if state.vectorBytes(register)&required != required {
				return false, true
			}
		}
	}
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	if form.memory >= 0 {
		memory := ins.Args[form.memory]
		native := pairedNative && x86OrdinaryNativeMemoryOperand(memory, arch) &&
			x86ResultIncomingPointerAddressIdentity(memory, state, arch)
		// Logical FP/AUTO bytes and bound DATA reads are not native backing
		// or permission to dereference an incoming pointer.
		if !native && (form.expand || form.mask >= 0) && !x86ResultRead(memory, int64(form.byteWidth), state, owned, arch) {
			return false, true
		}
		if !form.expand {
			if native {
				return true, true // Only the emitted compact prefix changes; no reusable memory facts.
			}
			return x86ResultStore(memory, int64(form.byteWidth), state, owned, resultOffset, arch), true
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth, required, false)
	return true, true // EVEX clears wider aliases; FLAGS, DF and K are unchanged.
}
