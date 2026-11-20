package plan9asm

// A block transfer selects a 128/256-bit chunk. Unknown bytes elsewhere in
// the source are not dependencies; masked merge bytes retain both possibilities.
// This numerical effect never creates native memory or initialized pointers.
func x86ResultBlockTransfer(ins Instr, form x86InsertExtractForm, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) bool {
	return x86ResultBlockTransferWithNativeMemory(ins, form, state, owned, resultOffset, arch, false)
}

// This private counterpart consumes the paired exact volatile tuple access or
// original E6NF masked-store opcode. Continuation supplies numerical bytes for
// reads only; stores establish no memory facts or raw/caller permission.
func x86LoweredBlockNativeMemory(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, recognized, err := x86InsertExtractProperties(ins, arch)
	if !recognized || err != nil || form.undefinedOpcode() || form.spec.scalar || form.memory < 0 {
		return false, false
	}
	memory := ins.Args[form.memory]
	if memory.Kind != OpMem || memory.Mem.Sym != "" || !x86OrdinaryNativeMemoryOperand(memory, arch) {
		return false, false
	}
	address := x86ResultIncomingPointerReadAddressIdentity(memory, state, arch)
	if form.memoryWrite {
		address = x86ResultIncomingPointerAddressIdentity(memory, state, arch)
	}
	if !address {
		return false, true
	}
	return x86ResultBlockTransferWithNativeMemory(ins, form, state, owned, resultOffset, arch, true), true
}

func x86ResultBlockTransferWithNativeMemory(ins Instr, form x86InsertExtractForm, state *x86ResultState,
	owned []bool, resultOffset int64, arch string, nativeMemory bool) bool {
	if form.undefinedOpcode() || form.spec.scalar || form.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		return false
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	chunk := x86CallerVectorByteMask(int64(form.spec.chunk))
	source := chunk
	if form.spec.insert && form.memory >= 0 {
		// E6NF reads its entire native tuple even for a zero mask, an
		// unobserved chunk or an independently initialized return value.
		if !nativeMemory && !x86ResultRead(ins.Args[form.memory], int64(form.spec.chunk), state, owned, arch) {
			return false
		}
	} else {
		operand := ins.Args[form.source]
		index, valid := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
		if !valid {
			return false
		}
		source = state.vectorBytes(index)
	}
	inputBytes, baseBytes := form.blockInputBytes()
	known := source & inputBytes
	if form.spec.insert {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.base].Reg, form.width)
		known = state.vectorBytes(index)&baseBytes | known<<uint(form.offset)
	} else {
		known >>= uint(form.offset)
	}
	destination := ins.Args[form.destination]
	if form.memoryWrite {
		if known&chunk != chunk {
			return false
		}
		if nativeMemory && x86ResultNamedPredicateInstruction(ins) && ins.x86NumericalRead == nil &&
			x86OrdinaryNativeMemoryOperand(destination, arch) &&
			x86ResultIncomingPointerAddressIdentity(destination, state, arch) {
			return true // A native masked store neither reads nor initializes inactive bytes.
		}
		if form.mask >= 0 {
			// A defined mask need not write any byte. The destination must
			// already be numerical on every inactive-store path. Its read
			// authority still cannot expand the separate write envelope.
			if !x86ResultRead(destination, int64(form.output), state, owned, arch) {
				return false
			}
		}
		return x86ResultStore(destination, int64(form.output), state, owned, resultOffset, arch)
	}
	index, valid := amd64VectorRegisterIndex(destination.Reg, form.output)
	if !valid {
		return false
	}
	if form.mask >= 0 && !form.zeroing {
		known &= state.vectorBytes(index)
	}
	state.writeVector(index, form.output, known, false)
	return true
}
