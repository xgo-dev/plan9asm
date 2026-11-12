package plan9asm

// An absent snapshot is not evidence of the decoder's actual VEX mode.
type x86RawExplicitMaskMoveIdentity struct {
	arch    string
	encoded bool
}

func x86ExplicitMaskMoveRawIdentity(ins Instr, arch string) x86RawExplicitMaskMoveIdentity {
	if _, known, err := x86ExplicitMaskMoveProperties(ins.Op, ins, arch); !known || err != nil || !ins.x86Encoded {
		return x86RawExplicitMaskMoveIdentity{}
	}
	return x86RawExplicitMaskMoveIdentity{arch, true}
}

func x86RawExplicitMaskMoveSource(ins Instr, arch string) bool {
	f, known, err := x86ExplicitMaskMoveProperties(ins.Op, ins, arch)
	return known && err == nil && ins.x86SourceRaw != nil &&
		ins.x86SourceRaw.explicitMaskMove.arch == arch &&
		ins.x86SourceRaw.explicitMaskMove == x86ExplicitMaskMoveRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, f.memory) && x86Mode32VectorRegisterContext(ins, arch) == nil
}

func x86ExplicitMaskMoveRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay == nil {
		return false
	}
	for _, ins := range fn.x86RawReplay.decoded {
		if _, known, _ := x86ExplicitMaskMoveProperties(ins.Op, ins, arch); known {
			return true
		}
	}
	return false
}

// Continued execution of the exact paired operation supplies active loaded
// lanes; inactive lanes are zero. This grants no backing, bounds, future-read
// fact or entry permission. Stores change no numerical memory facts.
func x86ResultExplicitMaskMoveStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string, native bool) (bool, bool) {
	f, known, err := x86ExplicitMaskMoveProperties(ins.Op, ins, arch)
	if !known || err != nil || x86Mode32VectorRegisterContext(ins, arch) != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawExplicitMaskMoveSource(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil // This exact paired effect only.
	}
	mask, _ := amd64VectorRegisterIndex(ins.Args[1].Reg, f.byteWidth)
	if required := f.signByteInputs(); state.vectorBytes(mask)&required != required {
		return false, true
	}
	width := int64(f.byteWidth)
	memory := ins.Args[f.memory]
	if !f.load && (memory.Kind == OpFP && memory.FPOffset < resultOffset || memory.Kind == OpSym ||
		memory.Kind == OpMem && memory.Mem.Sym != "") {
		return false, true // Readable parameter/static bytes are not a writable result/backing role.
	}
	if !f.load && !x86ResultPackedVectorRead(ins.Args[0], width, state, owned, arch) {
		return false, true
	}
	if native && ins.x86NumericalRead == nil && x86OrdinaryNativeMemoryOperand(memory, arch) {
		address := x86ResultIncomingPointerAddressIdentity(memory, state, arch)
		if f.load {
			address = x86ResultIncomingPointerReadAddressIdentity(memory, state, arch)
		}
		if !address {
			return false, true
		}
	} else if !x86ResultRead(memory, width, state, owned, arch) {
		// A logical masked store cannot initialize an unknown old byte: an
		// inactive lane preserves it. A full prior NUM tuple stays NUM.
		return false, true
	}
	if f.load {
		destination, _ := amd64VectorRegisterIndex(ins.Args[2].Reg, f.byteWidth)
		state.writeVector(destination, f.byteWidth, x86CallerVectorByteMask(width), false)
	}
	return true, true // FLAGS, DF, GP, mask and all memory facts are unchanged.
}

func x86CallerExplicitMaskMoveStep(ins *Instr, f x86ExplicitMaskMoveForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	mask := x86CallerVectorRoot(ins.Args[1].Reg)
	if required := f.signByteInputs(); state.vectors[mask]&required != required {
		return false
	}
	if !f.load {
		data := x86CallerVectorRoot(ins.Args[0].Reg)
		required := x86CallerVectorByteMask(int64(f.byteWidth))
		if state.vectors[data]&required != required {
			return false
		}
	}
	if !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.byteWidth), !f.load) {
		return false // The possible full tuple keeps independent caller bounds.
	}
	if f.load {
		state.vectors[x86CallerVectorRoot(ins.Args[2].Reg)] = ^uint64(0)
	}
	return true
}
