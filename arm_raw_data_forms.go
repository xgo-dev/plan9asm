package plan9asm

// armRawDataForm registers the existing typed data lowerers that do not write
// APSR.NZCV. Emission and the source-status proof consume the same decoder.
// This is not a native-entry or complete machine-effect contract: GP writes
// conservatively invalidate typed value witnesses, and unknown WORDs stay opaque.
type armRawDataForm struct {
	family    string
	condition string
	gpWrites  armKernelState
	lower     func(*armCtx) error
}

func armRawCoreWrites(registers ...int) armKernelState {
	var writes armKernelState
	for _, register := range registers {
		if register >= 0 && register < 15 {
			writes |= 1 << register
			if register == 13 {
				writes |= armKernelRegBit(SP)
			}
		}
	}
	return writes
}

func armRawDirectionWrites(write bool, registers ...int) armKernelState {
	if !write {
		return 0
	}
	return armRawCoreWrites(registers...)
}

func armRawPostIndexWrites(base, offset int) armKernelState {
	return armRawDirectionWrites(offset != 15, base)
}

func decodeARMRawDataForm(ins Instr) (armRawDataForm, bool) {
	if ins.Op != OpWORD || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return armRawDataForm{}, false
	}
	word := uint32(ins.Args[0].Imm)
	if form, ok := decodeARMRawNEONStructureFourMultiple(word); ok {
		return armRawDataForm{
			family:    "StructureFourMultiple",
			condition: "",
			gpWrites:  armRawPostIndexWrites(form.base, form.offset),
			lower:     func(c *armCtx) error { return c.lowerRawNEONStructureFourMultiple(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONModifiedImmediate(word); ok {
		return armRawDataForm{
			family:    "ModifiedImmediate",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONModifiedImmediate(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONCoreLaneMove(word); ok {
		return armRawDataForm{
			family:    "CoreLaneMove",
			condition: form.condition,
			gpWrites:  armRawDirectionWrites(!form.toVector, form.core),
			lower:     func(c *armCtx) error { return c.lowerRawNEONCoreLaneMove(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONStructureOneLane(word); ok {
		return armRawDataForm{
			family:    "StructureOneLane",
			condition: "",
			gpWrites:  armRawPostIndexWrites(form.base, form.offset),
			lower:     func(c *armCtx) error { return c.lowerRawNEONStructureLane(form, 1) },
		}, true
	}
	if form, ok := decodeARMRawNEONStructureFourLane(word); ok {
		return armRawDataForm{
			family:    "StructureFourLane",
			condition: "",
			gpWrites:  armRawPostIndexWrites(form.base, form.offset),
			lower:     func(c *armCtx) error { return c.lowerRawNEONStructureFourLane(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONTranspose(word); ok {
		return armRawDataForm{
			family:    "Transpose",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONTranspose(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONShiftRightNarrow(word); ok {
		return armRawDataForm{
			family:    "ShiftRightNarrow",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONShiftRightNarrow(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONBitClearImmediate(word); ok {
		return armRawDataForm{
			family:    "BitClearImmediate",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONBitClearImmediate(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONExtract(word); ok {
		return armRawDataForm{
			family:    "Extract",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONExtract(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONMoveNarrow(word); ok {
		return armRawDataForm{
			family:    "MoveNarrow",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONMoveNarrow(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONShiftInsert(word); ok {
		return armRawDataForm{
			family:    "ShiftInsert",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONShiftInsert(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONShiftRightImmediate(word); ok {
		return armRawDataForm{
			family:    "ShiftRightImmediate",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONShiftRightImmediate(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONReverse(word); ok {
		return armRawDataForm{
			family:    "Reverse",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONReverse(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONMultiplyLongLane(word); ok {
		return armRawDataForm{
			family:    "MultiplyLongLane",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONMultiplyLongLane(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONMultiplyLongVector(word); ok {
		return armRawDataForm{
			family:    "MultiplyLongVector",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONMultiplyLongVector(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONAddSub(word); ok {
		return armRawDataForm{
			family:    "AddSub",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONAddSub(form) },
		}, true
	}
	if form, ok := decodeARMRawVFPLoadStore(word); ok {
		return armRawDataForm{
			family:    "VFPLoadStore",
			condition: form.condition,
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawVFPLoadStore(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONShiftImmediate(word); ok {
		return armRawDataForm{
			family:    "ShiftImmediate",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONShiftImmediate(form) },
		}, true
	}
	if form, ok := decodeARMRawVFPMove(word); ok {
		return armRawDataForm{
			family:    "VFPMove",
			condition: form.condition,
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawVFPMove(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONPairwiseMinMax(word); ok {
		return armRawDataForm{
			family:    "PairwiseMinMax",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONPairwiseMinMax(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONMinMax(word); ok {
		return armRawDataForm{
			family:    "MinMax",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONMinMax(form) },
		}, true
	}
	if form, ok := decodeARMRawVFPScalarArithmetic(word); ok {
		return armRawDataForm{
			family:    "VFPScalarArithmetic",
			condition: form.condition,
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawVFPScalarArithmetic(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONMultiplyLane(word); ok {
		return armRawDataForm{
			family:    "MultiplyLane",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONMultiplyLane(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONConvertFloat32(word); ok {
		return armRawDataForm{
			family:    "ConvertFloat32",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONConvertFloat32(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONMoveLong(word); ok {
		return armRawDataForm{
			family:    "MoveLong",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONMoveLong(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONWideningAddSub(word); ok {
		return armRawDataForm{
			family:    "WideningAddSub",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONWideningAddSub(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONDup(word); ok {
		return armRawDataForm{
			family:    "Dup",
			condition: form.condition,
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONDup(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONStructureOne(word); ok {
		return armRawDataForm{
			family:    "StructureOne",
			condition: "",
			gpWrites:  armRawPostIndexWrites(form.base, form.offset),
			lower:     func(c *armCtx) error { return c.lowerRawNEONStructureOne(form) },
		}, true
	}
	if form, ok := decodeARMRawNEONBitwise(word); ok {
		return armRawDataForm{
			family:    "Bitwise",
			condition: "",
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawNEONBitwise(form) },
		}, true
	}
	if form, ok := decodeARMRawSXTB(word); ok {
		return armRawDataForm{
			family:    "SXTB",
			condition: form.condition,
			gpWrites:  armRawCoreWrites(form.destination),
			lower:     func(c *armCtx) error { return c.lowerRawSXTB(form) },
		}, true
	}
	if form, ok := decodeARMRawVMOVPair(word); ok {
		return armRawDataForm{
			family:    "VMOVPair",
			condition: form.condition,
			gpWrites:  armRawDirectionWrites(!form.toFloat, form.firstCore, form.secondCore),
			lower:     func(c *armCtx) error { return c.lowerRawVMOVPair(form) },
		}, true
	}
	if form, ok := decodeARMRawVFPMultiple(word); ok {
		return armRawDataForm{
			family:    "VFPMultiple",
			condition: form.condition,
			gpWrites:  armRawDirectionWrites(form.writeback, form.base),
			lower:     func(c *armCtx) error { return c.lowerRawVFPMultiple(form) },
		}, true
	}
	if form, ok := decodeARMRawVFPImmediate(word); ok {
		return armRawDataForm{
			family:    "VFPImmediate",
			condition: form.condition,
			gpWrites:  0,
			lower:     func(c *armCtx) error { return c.lowerRawVFPImmediate(form) },
		}, true
	}
	return armRawDataForm{}, false
}
