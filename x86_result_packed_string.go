package plan9asm

// All eight string-compare names share the emitter's complete imm8/X/m128/X
// grammar. Both X inputs are read before the implicit CX/X0 overwrite. Even
// explicit zero lengths do not shrink the architectural 128-bit memory input.
// This observer grants no pointee, alignment, caller or native-entry authority.
func x86ResultPackedStringStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86ResultPackedStringStepWithRead(ins, state, owned, arch, false)
}

func x86ResultPackedStringStepWithRead(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	spec, known, err := amd64PackedStringCompareProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	if spec.explicitLength && (!x86ResultRead(Operand{Kind: OpReg, Reg: AX}, 4, state, owned, arch) ||
		!x86ResultRead(Operand{Kind: OpReg, Reg: DX}, 4, state, owned, arch)) {
		return false, true
	}
	if !x86ResultRead(ins.Args[2], 16, state, owned, arch) ||
		!x86ResultReadWithNativeContinuation(ins, ins.Args[1], 16, state, owned, arch, nativeRead) {
		return false, true
	}
	output, width, zeroUpper := spec.resultEffect()
	if spec.maskResult {
		index, _ := amd64ParseXReg(output)
		state.writeVector(index, width, 0xffff, !zeroUpper)
	} else {
		index, _, _ := x86ResultGP(output, int64(width), arch)
		state.gp[index] = 0xff // Architectural r32 write zero-extends the GP alias.
		state.canonicalGP[index] = 0
		state.pointerGP[index], state.callerAddressGP[index] = false, false
		state.callerAddressOrigin[index] = 0
		state.resultAddressGP[index] = x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP[index] = x86ResultSlotAddress{}
		}
	}
	state.flags = x86ByteFlagsAll // CF/ZF/SF/OF defined, PF/AF zero; never DF.
	state.bitScanPending = x86ResultBitScanPending{}
	state.predicate = x86ResultPredicate{}
	return true, true
}
