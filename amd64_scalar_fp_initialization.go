package plan9asm

// This private transfer extends the existing must-initialized result analysis
// for logical scalar views and existing exact same-Void-source whole128 caller
// reads. It does not expand the public asmdecl-filter query, caller admission,
// frame backing, or pointer permissions.
func checkX86ScalarFPResultInitialization(fn Func, sig FuncSig, arch string) error {
	reads := x86ScalarFPCallerReads(fn, sig, arch)
	if fn.x86DirectTailRoot != nil {
		reads = nil // No helper may borrow another TEXT's caller-read ordinal.
	}
	return checkX86ABI0ResultInitializationAtSource(fn, sig, arch,
		func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
			if read, present := reads[ordinal]; present {
				return read.transfer(ins, state, owned, resultOffset, arch)
			}
			return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
		}, true)
}

func x86ScalarFPResultTransfer(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
	if accepted, known := x86ResultSingleSourceNarrowStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultExplicitMaskMoveStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	if accepted, known := x86MaskLogicalResultStep(ins, state, arch); known {
		return accepted
	}
	if accepted, known := x86MaskVectorResultStep(ins, state, arch); known {
		return accepted
	}
	if accepted, known := x86ResultNonTemporalVectorStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	if accepted, known := x86MaskValueResultStep(ins, state, arch); known {
		return accepted
	}
	if accepted, known := x86ResultX87ValueStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultX87StatusProjection(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultSDKLiteralStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultNumericalReadStep(ins, state, owned, resultOffset, arch); known {
		return accepted
	}
	if accepted, known := x86ResultFloatingHelperStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86ResultFloatCompareStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known {
		return err == nil && x86ResultPackedVectorMoveTransfer(ins, form, state, owned, resultOffset, arch, false)
	}
	if form, known, err := x86PackedLogicalProperties(ins, arch); known {
		return err == nil && x86ScalarFPLogicalTransfer(ins, form, state, owned, arch)
	}
	if f, known, err := x86GPSIMDTransferProperties(ins, arch); known {
		return err == nil && x86ResultGPSIMDTransfer(ins, f, state, owned, resultOffset, arch)
	}
	if form, recognized, err := x86FloatAddSubProperties(ins, arch); recognized {
		return err == nil && x86ScalarFPFloatBinaryTransfer(ins, form.x86FloatBinaryForm, state, owned, arch)
	}
	if form, recognized, err := x86FloatMulDivProperties(ins, arch); recognized {
		return err == nil && x86ScalarFPFloatBinaryTransfer(ins, form.x86FloatBinaryForm, state, owned, arch)
	}
	if accepted, known := x86ResultFloatMinMaxStep(ins, state, owned, arch, false); known {
		return accepted
	}
	if accepted, known := x86MaskMoveResultStep(ins, state, owned, resultOffset, arch, false); known {
		return accepted
	}
	if form, known, err := x86PackedWordMultiplyProperties(ins.Op, ins, arch); known {
		// A sparse low-product NUM projection is not the complete source
		// input contract. Keep the existing word-family guard after marked
		// literal/read validation, including Void and paired native reads.
		return err == nil && x86ResultFixedVectorInputs(ins, form.x86PackedBinaryForm, false, state, owned, arch)
	}
	form, recognized, err := amd64ScalarVectorMoveProperties(ins, arch)
	if !recognized || form.spec.legacy {
		return x86ResultTransfer(ins, state, owned, resultOffset, arch)
	}
	return err == nil && x86ScalarVectorMoveResultTransfer(ins, form, state, owned, resultOffset, arch, false)
}

// Every typed X/Y/Z form consumes the same physical-bank byte domain. Physical
// MMX remains separate; no vector effect turns a native pointer into FP data.
func x86ScalarFPLogicalTransfer(ins Instr, form x86PackedLogicalForm, state *x86ResultState, owned []bool, arch string) bool {
	return x86ScalarFPLogicalTransferWithRead(ins, form, state, owned, arch, false)
}

func x86ScalarFPLogicalTransferWithRead(ins Instr, form x86PackedLogicalForm, state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if form.mmx {
		return false
	}
	xreg := func(operand Operand) (int, bool) {
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		return index, operand.Kind == OpReg && valid && index < len(state.xmm) && (arch != "386" || index < 8)
	}
	second, valid := xreg(ins.Args[form.second])
	if !valid {
		return false
	}
	destination, valid := xreg(ins.Args[form.destination])
	if !valid {
		return false
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	first := x86CallerVectorByteMask(int64(form.byteWidth))
	if form.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, form.source, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false // Even a zero mask supplies no missing native envelope.
		}
	} else {
		index, valid := xreg(ins.Args[form.first])
		if !valid {
			return false
		}
		first = state.vectorBytes(index)
	}
	known := x86PackedLogicalDefinedBytes(ins, form, first,
		state.vectorBytes(second), state.vectorBytes(destination))
	state.writeVector(destination, form.byteWidth, known, form.legacy)
	return true
}
