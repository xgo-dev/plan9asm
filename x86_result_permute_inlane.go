package plan9asm

// Only the lowering-paired E4NF read supplies conditional native bytes. Raw
// boundaries, caller memory, SDK literals and native entry retain their owners.
func x86ResultElementPermuteStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	f, known, err := x86ElementPermuteProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	var source uint64
	if f.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[f.source], int64(f.memoryBytes), state, owned, arch, native) {
			return false, true
		}
		source = x86CallerVectorByteMask(int64(f.memoryBytes))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[f.source].Reg, f.byteWidth)
		source = state.vectorBytes(index)
	}
	var defined uint64
	if f.immediate {
		for output := 0; output < f.byteWidth; output++ {
			defined |= (source >> uint(f.sourceByte(output)) & 1) << uint(output)
		}
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[f.data].Reg, f.byteWidth)
		data, control := state.vectorBytes(index), source
		dataWidth := f.byteWidth
		if f.wholeVector {
			data, control = source, data
			if f.broadcast {
				dataWidth = f.memoryBytes
			}
		}
		dataMask := x86CallerVectorByteMask(int64(dataWidth))
		if data&dataMask != dataMask {
			return false, true // Even a dead variable permute consumes its numerical data input.
		}
		bytes := f.bits / 8
		for lane := 0; lane < f.byteWidth/bytes; lane++ {
			controlByte := lane * bytes
			if f.broadcast && !f.wholeVector {
				controlByte = 0
			}
			if control>>uint(controlByte)&1 == 0 {
				return false, true // Only selector bits in the low control byte are read.
			}
		}
		defined = x86CallerVectorByteMask(int64(f.byteWidth))
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	if f.mask >= 0 && !f.zeroing {
		defined &= state.vectorBytes(destination)
	}
	state.writeVector(destination, f.byteWidth, defined, false)
	return true, true // FLAGS, DF, GP identities, masks and independent storage survive.
}
