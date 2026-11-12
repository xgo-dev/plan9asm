package plan9asm

func x86RawFP16SqrtSource(ins Instr, arch string) bool {
	f, known, err := x86SqrtProperties(ins, arch)
	return known && err == nil && f.bits == 16 && x86RawOrdinaryVectorSource(ins, arch)
}

// Sqrt computes only from its first operand. Scalar VEX/EVEX copies the
// second operand's upper X bytes without requiring its unused low scalar.
// Unknown copied bytes stay unknown; no pointer or storage facts are created.
func x86ResultSqrtStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	f, known, err := x86SqrtProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	if f.bits == 16 {
		if !nativeRead || !x86RawFP16SqrtSource(ins, arch) {
			return false, true
		}
		// The original identity above remains mandatory. This local projection
		// lets the shared numerical read consume the paired native access only.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	input := ^uint64(0)
	if f.memory >= 0 {
		if !f.scalar && ins.Args[0].Kind == OpFP {
			return false, true // Packed original memory needs contiguous native backing.
		}
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[0], int64(f.memoryBytes), state, owned, arch, nativeRead) {
			return false, true
		}
	} else {
		source, _ := amd64VectorRegisterIndex(ins.Args[0].Reg, f.byteWidth)
		input = state.vectorBytes(source)
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	old := state.vectorBytes(destination)
	upper, _ := amd64VectorRegisterIndex(ins.Args[f.second].Reg, f.byteWidth)
	value, valid := x86SqrtDefinedBytes(f, input, state.vectorBytes(upper), old)
	if !valid {
		return false, true
	}
	state.writeVector(destination, f.byteWidth, value, f.legacy)
	return true, true
}
