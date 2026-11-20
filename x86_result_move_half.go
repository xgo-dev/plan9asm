package plan9asm

// Byte selectors do not initialize an unknown copied half. The native m64
// access is mandatory independently of any selected output, including Void.
func x86ResultMoveHalfStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string, native bool) (bool, bool) {
	form, known, err := x86MoveHalfProperties(ins.Op, ins, arch)
	if !known || err != nil || form.undocumentedPDRegister {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawMoveHalfSource(ins, arch) {
			return false, true
		}
		// Only this exact sealed source may share the paired projection.
		// Register-only aliases supply no native address, caller or entry fact.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	source := uint64(0xff)
	if form.memory >= 0 && !form.store {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[form.source], 8, state, owned, arch, native) {
			return false, true
		}
	} else {
		index, _ := amd64ParseXReg(ins.Args[form.source].Reg)
		source = state.vectorBytes(index) >> uint(form.sourceLane*8) & 0xff
	}
	if form.store {
		if source != 0xff {
			return false, true
		}
		destination := ins.Args[form.destination]
		if x86ResultScalarLaneNativeStore(ins, destination, state, arch, native) {
			return true, true // The access creates no later-read or storage fact.
		}
		return x86ResultStore(destination, 8, state, owned, resultOffset, arch), true
	}
	base, _ := amd64ParseXReg(ins.Args[form.base].Reg)
	destination, _ := amd64ParseXReg(ins.Args[form.destination].Reg)
	lane := uint(form.outputLane * 8)
	mask := uint64(0xff) << lane
	defined := state.vectorBytes(base)&0xffff&^mask | source<<lane
	state.writeVector(destination, 16, defined, !form.spec.vector)
	return true, true // FLAGS, DF, masks, pointers and unrelated storage survive.
}

func x86RawMoveHalfSource(ins Instr, arch string) bool {
	form, known, err := x86MoveHalfProperties(ins.Op, ins, arch)
	return known && err == nil && (form.spec.vector || form.spec.registerOnly) && x86RawOrdinaryVectorSource(ins, arch)
}
