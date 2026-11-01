package plan9asm

// These are defined-byte effects only. Caller-region native reads retain their
// independent bounds proof; declaration-only results require initialized bytes.
func x86CallerScalarLaneStep(ins *Instr, f x86ScalarLaneForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	width := int64(f.bits / 8)
	if f.memory >= 0 && !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, width, !f.insert) {
		return false
	}
	if f.insert {
		known := x86CallerVectorByteMask(width)
		if f.memory < 0 {
			root, valid := x86CallerGP(f.transferReg)
			_, pointer := state.callers[root]
			if !valid || root == SP || root == BP || pointer || uint64(state.known[root])&known != known {
				return false
			}
		}
		destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
		base := state.vectors[x86CallerVectorRoot(ins.Args[f.base].Reg)]
		state.vectors[destination] = x86ScalarLaneInsertKnown(f, base, known, state.vectors[destination])
		return true
	}
	source := state.vectors[x86CallerVectorRoot(ins.Args[f.source].Reg)]
	low := x86CallerVectorByteMask(width)
	if source>>uint(f.offset)&low != low {
		return false
	}
	if f.memory >= 0 {
		return true
	}
	return x86CallerNumericWrite(f.transferReg, int64(f.gpBits/8), state)
}

func x86ResultScalarLaneStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	return x86ResultScalarLaneStepWithRead(ins, state, owned, resultOffset, arch, false)
}

func x86ResultScalarLaneStepWithRead(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string, conditionalNativeRead bool) (bool, bool) {
	f, known, err := x86ScalarLaneProperties(ins, arch)
	if !known {
		// Scalar and block transfers share the validated imm8/source/target
		// grammar, but select bytes from their distinct physical widths.
		ps, recognized, failure := x86InsertExtractProperties(ins, arch)
		if !recognized {
			return false, false
		}
		if failure != nil {
			return false, true
		}
		if !ps.spec.scalar {
			return x86ResultBlockTransfer(ins, ps, state, owned, resultOffset, arch), true
		}
		return x86ResultScalarPSLaneStep(ins, ps, state, owned, resultOffset, arch, conditionalNativeRead), true
	}
	if err != nil {
		return false, true
	}
	width := int64(f.bits / 8)
	low := x86CallerVectorByteMask(width)
	if f.insert {
		if f.memory >= 0 {
			if !x86ResultReadWithNativeContinuation(ins, ins.Args[f.source], width, state, owned, arch, conditionalNativeRead) {
				return false, true
			}
		} else {
			readWidth := int64(4)
			if f.bits == 64 {
				readWidth = 8
			}
			index, _, valid := x86ResultGP(f.transferReg, readWidth, arch)
			if !valid || state.pointerGP[index] || uint64(state.gp[index])&low != low {
				return false, true
			}
		}
		base, _ := amd64ParseXReg(ins.Args[f.base].Reg)
		destination, _ := amd64ParseXReg(ins.Args[f.destination].Reg)
		state.writeVector(destination, 16,
			x86ScalarLaneInsertKnown(f, state.vectorBytes(base), low, state.vectorBytes(destination)), f.legacy)
		return true, true
	}
	source, _ := amd64ParseXReg(ins.Args[f.source].Reg)
	if uint64(state.xmm[source])>>uint(f.offset)&low != low {
		return false, true
	}
	destination := ins.Args[f.destination]
	if f.memory < 0 {
		destination.Reg = f.transferReg
		width = int64(f.gpBits / 8)
	}
	if x86ResultScalarLaneNativeStore(ins, destination, state, arch, conditionalNativeRead) {
		return true, true
	}
	return x86ResultStore(destination, width, state, owned, resultOffset, arch), true
}

// Only the paired exact-width volatile emitter may continue a named native
// scalar store. Its selected source bytes have already been checked; the
// write creates no numerical, storage, pointer or later-read fact.
func x86ResultScalarLaneNativeStore(ins Instr, destination Operand, state *x86ResultState, arch string, paired bool) bool {
	return paired && x86ResultNamedPredicateInstruction(ins) && ins.x86NumericalRead == nil &&
		x86OrdinaryNativeMemoryOperand(destination, arch) &&
		x86ResultIncomingPointerAddressIdentity(destination, state, arch)
}

func x86ResultScalarPSLaneStep(ins Instr, f x86InsertExtractForm, state *x86ResultState, owned []bool, resultOffset int64, arch string, conditionalNativeRead bool) bool {
	source := uint16(0)
	if f.memory >= 0 {
		if f.spec.insert && !x86ResultReadWithNativeContinuation(ins, ins.Args[f.memory], 4, state, owned, arch, conditionalNativeRead) {
			return false
		}
		source = 0xf
	} else {
		index, _ := amd64ParseXReg(ins.Args[f.source].Reg)
		source = state.xmm[index]
	}
	if !f.spec.insert {
		index, _ := amd64ParseXReg(ins.Args[f.source].Reg)
		if state.xmm[index]>>uint(f.offset)&0xf != 0xf {
			return false
		}
		if x86ResultScalarLaneNativeStore(ins, ins.Args[f.destination], state, arch, conditionalNativeRead) {
			return true
		}
		return x86ResultStore(ins.Args[f.destination], 4, state, owned, resultOffset, arch)
	}
	base, _ := amd64ParseXReg(ins.Args[f.base].Reg)
	destination, _ := amd64ParseXReg(ins.Args[f.destination].Reg)
	if f.memory < 0 {
		source >>= uint(f.immediate>>6) * 4
	}
	lane := uint(f.immediate>>4&3) * 4
	known := state.xmm[base]&^(uint16(0xf)<<lane) | (source&0xf)<<lane
	for index := 0; index < 4; index++ {
		if f.immediate&(1<<index) != 0 {
			known |= uint16(0xf) << uint(index*4)
		}
	}
	state.writeVector(destination, 16, uint64(known), f.spec.legacy)
	return true
}
