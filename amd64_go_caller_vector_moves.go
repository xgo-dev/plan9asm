package plan9asm

import "fmt"

func x86CallerVectorMoveKnown(ins Instr) bool {
	if _, known, err := x86Permute128Properties(ins.Op, ins, "amd64"); known {
		return err == nil && x86ResultNamedPredicateInstruction(ins) && !ins.x86Permute128VEX
	}
	if _, known, err := x86PackedDotProperties(ins.Op, ins, "amd64"); known {
		return err == nil && x86ResultNamedPredicateInstruction(ins)
	}
	if _, known, err := x86ExplicitMaskMoveProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if _, known, err := x86PackedAlignProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := x86SqrtProperties(ins, "amd64"); known {
		return err == nil && form.bits != 16
	}
	if _, known, err := x86ByteShuffleProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if _, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := x86PackedConversionProperties(ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if form, known, err := x86CLMULProperties(ins.Op, ins, "amd64"); known {
		return err == nil && form.memory < 0
	}
	if _, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if _, known, err := x86ScalarLaneProperties(ins, "amd64"); known {
		return err == nil
	}
	if _, known, err := x86AESProperties(ins.Op, ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := x86HorizontalIntegerProperties(ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if form, known, err := x86GPSIMDTransferProperties(ins, "amd64"); known {
		return err == nil && !form.mmx && !form.spec.rawOnly
	}
	if form, known, err := x86ImmediateShuffleProperties(ins, "amd64"); known {
		return err == nil && !form.spec.mmx
	}
	if _, known, err := x86PackedFloatShuffleProperties(ins.Op, ins, "amd64"); known {
		return err == nil && x86ResultNamedPredicateInstruction(ins)
	}
	if form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, "amd64"); known && form.legacy {
		return err == nil && form.memory < 0 && x86ResultNamedPredicateInstruction(ins)
	}
	if _, known, err := x86MaskVectorProperties(ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := x86PackedNarrowProperties(ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if form, known, err := x86PackedWordMultiplyProperties(ins.Op, ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if form, known, err := x86DwordProductProperties(ins.Op, ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if _, known, err := x86PackedSADProperties(ins, "amd64"); known {
		return err == nil
	}
	if form, known, err := x86PackedSubtractProperties(ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if _, recognized, err := x86FloatCompareProperties(ins, "amd64"); recognized {
		return err == nil
	}
	if form, known, err := x86PackedWrappingAddProperties(ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if form, known, err := x86PackedMultiplyAddProperties(ins.Op, ins, "amd64"); known {
		return err == nil && !form.mmx
	}
	if f, known, err := x86SignedPackedFloatProperties(ins, "amd64"); known {
		return err == nil && !f.mmx
	}
	if _, recognized, err := x86FloatArithmeticProperties(ins, "amd64", ""); recognized {
		return err == nil
	}
	if form, recognized, err := x86PackedExtendProperties(ins, "amd64"); recognized {
		return err == nil && (!form.signed || x86ResultNamedPredicateInstruction(ins))
	}
	if _, recognized, err := x86VectorZeroProperties(ins, "amd64"); recognized {
		return err == nil
	}
	if _, recognized, err := x86SignedIntegerFloatProperties(ins, "amd64"); recognized {
		return err == nil
	}
	if f, recognized, err := x86InsertExtractProperties(ins, "amd64"); recognized {
		return err == nil && !(f.mask >= 0 && f.memoryWrite)
	}
	if form, recognized, err := x86PackedShiftProperties(ins.Op, ins, "amd64"); recognized {
		return err == nil && !form.mmx
	}
	if _, recognized, err := x86HorizontalFloatProperties(ins, "amd64"); recognized {
		return err == nil
	}
	if form, recognized, err := x86PackedUnpackProperties(ins, "amd64"); recognized {
		return err == nil && !form.mmx
	}
	if form, recognized, err := x86PackedLogicalProperties(ins, "amd64"); recognized {
		return err == nil && !form.mmx
	}
	if amd64MaskMoveOperandsValid(ins, "amd64") {
		return true
	}
	if form, recognized, err := amd64PackedVectorMoveProperties(ins, "amd64"); recognized {
		return err == nil && !form.undefinedOpcode()
	}
	if form, recognized, err := amd64FMA3Properties(ins, "amd64"); recognized {
		return err == nil && !form.spec.rawOnly
	}
	form, recognized, err := amd64ScalarVectorMoveProperties(ins, "amd64")
	// The shared lowerer also models raw-only FP16 moves. Their caller-bank
	// permission needs its own complete source/runtime family, not inheritance
	// from the reviewed Go-named single/double-precision forms.
	return recognized && err == nil && !form.spec.rawOnly
}

func x86CloneCallerVectorState(vectors map[Reg]uint64, masks map[Reg]bool) (map[Reg]uint64, map[Reg]bool) {
	vectorCopy := make(map[Reg]uint64, len(vectors))
	for reg, known := range vectors {
		vectorCopy[reg] = known
	}
	maskCopy := make(map[Reg]bool, len(masks))
	for reg, known := range masks {
		maskCopy[reg] = known
	}
	return vectorCopy, maskCopy
}

func x86CallerVectorRoot(reg Reg) Reg {
	index, _ := amd64VectorRegisterIndex(reg, amd64VectorByteWidth(reg))
	return Reg(fmt.Sprintf("Z%d", index))
}

func x86CallerVectorByteMask(width int64) uint64 {
	if width <= 0 || width > 64 {
		return 0
	}
	if width == 64 {
		return ^uint64(0)
	}
	return uint64(1)<<uint(width) - 1
}

func x86CallerVectorMoveStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form, known, err := x86Permute128Properties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerPermute128Step(ins, form, state, proof)
	}
	if form, known, err := x86PackedDotProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerPackedDotStep(ins, form, state, proof)
	}
	if form, known, err := x86ExplicitMaskMoveProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerExplicitMaskMoveStep(ins, form, state, proof)
	}
	if form, known, err := x86SqrtProperties(*ins, "amd64"); known {
		return err == nil && x86CallerSqrtStep(ins, form, state, proof)
	}
	if form, known, err := x86ByteShuffleProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerByteShuffleStep(ins, form, state, proof)
	}
	if form, known, err := x86PackedConversionProperties(*ins, "amd64"); known {
		return err == nil && x86CallerPackedConversionStep(ins, form, state, proof)
	}
	if form, known, err := x86CLMULProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerCLMULStep(*ins, form, state)
	}
	if form, known, err := x86LegacyPackedMoveProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerLegacyPackedMoveStep(ins, form, state, proof)
	}
	if form, known, err := x86ScalarLaneProperties(*ins, "amd64"); known {
		return err == nil && x86CallerScalarLaneStep(ins, form, state, proof)
	}
	if form, known, err := x86AESProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerAESByteStep(ins, form, state, proof)
	}
	if form, known, err := x86HorizontalIntegerProperties(*ins, "amd64"); known {
		return err == nil && x86CallerHorizontalIntegerStep(ins, form, state, proof)
	}
	if form, known, err := x86GPSIMDTransferProperties(*ins, "amd64"); known {
		return err == nil && x86CallerGPSIMDTransferStep(ins, form, state, proof)
	}
	if form, known, err := x86ImmediateShuffleProperties(*ins, "amd64"); known {
		return err == nil && x86CallerImmediateShuffleStep(ins, form, state, proof)
	}
	if form, known, err := x86PackedFloatShuffleProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerPackedFloatShuffleStep(ins, form, state, proof)
	}
	if form, known, err := x86IntegerMinMaxProperties(ins.Op, *ins, "amd64"); known && form.legacy {
		// Existing register callers share the lane rule. A caller slice does
		// not grant the original m128's separate native alignment contract.
		return err == nil && form.memory < 0 && x86ResultNamedPredicateInstruction(*ins) &&
			x86CallerPackedLaneArithmeticStep(ins, form.x86PackedBinaryForm, form.spec.laneBits, state, proof)
	}
	if form, known, err := x86PackedAlignProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerPackedAlignStep(ins, form, state, proof)
	}
	if form, known, err := x86MaskVectorProperties(*ins, "amd64"); known {
		return err == nil && x86CallerMaskVectorStep(ins, form, state)
	}
	if form, known, err := x86PackedNarrowProperties(*ins, "amd64"); known {
		return err == nil && x86CallerPackedNarrowStep(ins, form, state, proof)
	}
	if form, known, err := x86PackedLowMultiplyProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerPackedLaneArithmeticStep(ins, form.x86PackedBinaryForm, form.spec.laneBits, state, proof)
	}
	if form, known, err := x86PackedWordMultiplyProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerPackedLaneArithmeticStep(ins, form.x86PackedBinaryForm, 16, state, proof)
	}
	if form, known, err := x86DwordProductProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerDwordProductStep(ins, form, state, proof)
	}
	if form, known, err := x86PackedSADProperties(*ins, "amd64"); known {
		return err == nil && x86CallerSADStep(ins, form, state, proof)
	}
	if form, known, err := x86PackedSubtractProperties(*ins, "amd64"); known {
		return err == nil && x86CallerPackedLaneArithmeticStep(ins, form.x86PackedBinaryForm, form.laneBits, state, proof)
	}
	if form, recognized, err := x86FloatCompareProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerFloatCompareStep(ins, form, state, proof)
	}
	if form, known, err := x86PackedWrappingAddProperties(*ins, "amd64"); known {
		return err == nil && x86CallerPackedWrappingAddStep(ins, form, state, proof)
	}
	if form, known, err := x86PackedMultiplyAddProperties(ins.Op, *ins, "amd64"); known {
		return err == nil && x86CallerWordMultiplyAddStep(ins, form, state, proof)
	}
	if f, known, err := x86SignedPackedFloatProperties(*ins, "amd64"); known {
		return err == nil && x86CallerSignedPackedFloatStep(ins, f, state, proof)
	}
	if form, recognized, err := x86FloatArithmeticProperties(*ins, "amd64", ""); recognized {
		return err == nil && x86CallerFloatBinaryStep(ins, form.x86FloatBinaryForm, state, proof)
	}
	if form, recognized, err := x86PackedExtendProperties(*ins, "amd64"); recognized {
		return err == nil && (!form.signed || x86ResultNamedPredicateInstruction(*ins)) &&
			x86CallerPackedExtendStep(ins, form, state, proof)
	}
	if form, recognized, err := x86VectorZeroProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerVectorZeroStep(form, state)
	}
	if f, recognized, err := x86SignedIntegerFloatProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerSignedIntegerFloatStep(ins, f, state, proof)
	}
	if f, recognized, err := x86InsertExtractProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerInsertExtractStep(ins, f, state, proof)
	}
	if form, recognized, err := x86PackedShiftProperties(ins.Op, *ins, "amd64"); recognized {
		return err == nil && x86CallerPackedShiftStep(ins, form, state, proof)
	}
	if form, recognized, err := x86HorizontalFloatProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerHorizontalFloatStep(ins, form, state, proof)
	}
	if form, recognized, err := x86PackedUnpackProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerPackedUnpackStep(ins, form, state, proof)
	}
	if form, recognized, err := x86PackedLogicalProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerPackedLogicalStep(ins, form, state, proof)
	}
	if amd64MaskMoveOperandsValid(*ins, "amd64") {
		return x86CallerMaskMoveStep(ins, state, proof)
	}
	if form, recognized, err := amd64PackedVectorMoveProperties(*ins, "amd64"); recognized {
		return err == nil && x86CallerPackedVectorMoveStep(ins, form, state, proof)
	}
	if form, recognized, err := amd64FMA3Properties(*ins, "amd64"); recognized {
		return err == nil && x86CallerFMA3Step(ins, form, state, proof)
	}
	form, recognized, err := amd64ScalarVectorMoveProperties(*ins, "amd64")
	if !recognized || err != nil || form.spec.rawOnly || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := int64(form.spec.bits / 8)
	lowMask := x86CallerVectorByteMask(width)
	if form.memory >= 0 {
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, width, form.memoryWrite) {
			return false
		}
		if form.memoryWrite {
			source := x86CallerVectorRoot(ins.Args[form.low].Reg)
			return state.vectors[source]&lowMask == lowMask
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	old := state.vectors[destination]
	if form.spec.legacy || form.legacyZero {
		if form.memory >= 0 || form.literal {
			// A legacy memory load zeroes the rest of XMM but preserves the
			// upper Y/Z aliases. Register copies preserve the old upper XMM.
			state.vectors[destination] = old | x86CallerVectorByteMask(16)
		} else {
			source := x86CallerVectorRoot(ins.Args[form.low].Reg)
			state.vectors[destination] = old&^lowMask | state.vectors[source]&lowMask
		}
		return true
	}
	known := ^uint64(0)
	if form.memory < 0 && !form.literal {
		low := state.vectors[x86CallerVectorRoot(ins.Args[form.low].Reg)] & lowMask
		upperMask := x86CallerVectorByteMask(16) &^ lowMask
		upper := state.vectors[x86CallerVectorRoot(ins.Args[form.upper].Reg)] & upperMask
		known = ^x86CallerVectorByteMask(16) | low | upper
	}
	if form.mask >= 0 && !form.zeroing {
		// The mask is initialized, not assumed all-one: either active data
		// or the old low element may survive. Higher lanes follow the move
		// form's upper merge/zero rules independently of that mask bit.
		known = known&^lowMask | known&old&lowMask
	}
	state.vectors[destination] = known
	return true
}

func x86CallerMaskMoveStep(ins *Instr, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	bits := amd64MaskMoveSpecs[ins.Op]
	width := int64(bits / 8)
	source, destination := ins.Args[0], ins.Args[1]
	if source.Kind == OpMem {
		if !x86CallerOrdinaryMemoryStep(ins, 0, state, proof, width, false) {
			return false
		}
	} else if amd64IsKOperand(source) {
		if !state.masks[source.Reg] {
			return false
		}
	} else if !x86CallerNumericRead(source, width, state) {
		return false // In particular, GP pointer bits cannot become mask data.
	}
	if destination.Kind == OpMem {
		return x86CallerOrdinaryMemoryStep(ins, 1, state, proof, width, true)
	}
	if amd64IsKOperand(destination) {
		state.masks[destination.Reg] = true
		return true
	}
	// All KMOV GP destinations zero-extend the transferred value, including
	// B/W/D, so the complete GP result is numeric; SP/BP/g stay forbidden.
	return x86CallerNumericWrite(destination.Reg, 8, state)
}

func x86CallerMoveMemoryShape(ins Instr, index int) (width int64, write, valid bool) {
	return x86InstructionMemoryShape(ins, index, "amd64")
}

func x86InstructionMemoryShape(ins Instr, index int, arch string) (width int64, write, valid bool) {
	if f, known, err := x86SingleSourceNarrowProperties(ins.Op, ins, arch); known {
		return int64(f.outputBytes), true, err == nil && !f.undefinedOpcode() && f.memory >= 0 && f.memory == index
	}
	if form, known, err := x86PackedPrecisionProperties(ins.Op, ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if form, known, err := x86ExplicitMaskMoveProperties(ins.Op, ins, arch); known {
		return int64(form.byteWidth), !form.load, err == nil && form.memory == index
	}
	if form, known, err := x86SqrtProperties(ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory >= 0 && form.memory == index
	}
	if known, _ := x86SizedNOPProperties(ins, arch); known {
		return 0, false, false // An encoding-only ModRM operand grants no access or caller envelope.
	}
	if form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, arch); known {
		return int64(form.move.byteWidth), !form.spec.load,
			err == nil && !form.trap && form.move.memory == index
	}
	if form, known, err := x86CRC32Properties(ins.Op, ins, arch); known {
		return int64(form.bits / 8), false, err == nil && index == 0 && isAMD64MemoryOperand(form.source)
	}
	if form, known, err := x86ScalarBitFieldProperties(ins.Op, ins, arch); known {
		return int64(form.bits / 8), false, err == nil && index == 1 && isAMD64MemoryOperand(form.source)
	}
	if form, known, err := x86BLSProperties(ins.Op, ins, arch); known {
		return int64(form.spec.bits / 8), false, err == nil && index == 0 && isAMD64MemoryOperand(form.source)
	}
	if form, known, err := x86ByteShuffleProperties(ins.Op, ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if form, known, err := x86CLMULProperties(ins.Op, ins, arch); known {
		return int64(form.byteWidth), false, err == nil && form.memory >= 0 && index == form.memory
	}
	if form, known, err := x86ExplicitIMULProperties(ins.Op, ins, arch); known {
		sourceIndex := 0
		if form.three {
			sourceIndex = 1
		}
		return int64(form.bits / 8), false, err == nil && index == sourceIndex && isAMD64MemoryOperand(form.source)
	}
	if form, known, err := x86AESProperties(ins.Op, ins, arch); known {
		return int64(form.byteWidth), false, err == nil && form.memory >= 0 && form.memory == index
	}
	if form, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch); known {
		return int64(form.bits / 8), false, err == nil && index == 0 && isAMD64MemoryOperand(form.source)
	}
	if form, known, err := x86ScalarLaneProperties(ins, arch); known {
		return int64(form.bits / 8), !form.insert, err == nil && form.memory == index
	}
	if form, known, err := x86HorizontalIntegerProperties(ins, arch); known {
		return int64(form.byteWidth), false, err == nil && !form.mmx && form.spec.vector && form.memory == index
	}
	if form, known, err := x86GPSIMDTransferProperties(ins, arch); known {
		return int64(form.bits / 8), form.memoryWrite, err == nil && !form.mmx && form.memory == index
	}
	if form, recognized, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch); recognized {
		return 16, form.memoryWrite, err == nil && x86Mode32VectorRegisterContext(ins, arch) == nil && form.memory == index
	}
	if form, recognized, err := x86LegacyIntegerArithmeticProperties(ins.Op, ins, arch); recognized {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if index < 0 || index >= len(ins.Args) || !isAMD64MemoryOperand(ins.Args[index]) {
		return 0, false, false
	}
	if form, known, err := x86ImmediateShuffleProperties(ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && !form.spec.legacy && form.memory == index
	}
	if form, known, err := x86PackedFloatShuffleProperties(ins.Op, ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && !form.legacy && form.memory == index
	}
	if form, known, err := x86PackedAlignProperties(ins.Op, ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && !form.legacy && form.memory == index
	}
	if form, known, err := x86Permute128Properties(ins.Op, ins, arch); known {
		return 32, false, err == nil && form.memory == index
	}
	if form, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if form, known, err := x86PackedPhysicalProperties(ins.Op, ins, arch, ""); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index &&
			(!form.mmx || form.spec.family == x86PackedAverage)
	}
	if form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && !form.mmx && form.memory == index
	}
	if form, known, err := x86PackedTestMaskProperties(ins.Op, ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if _, recognized, err := x86ConditionalSetProperties(ins.Op, ins, arch); recognized {
		return 1, true, err == nil && index == 0
	}
	if form, known, err := x86PackedNarrowProperties(ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if form, known, err := x86PackedSADProperties(ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if form, known, err := x86PackedSubtractProperties(ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if form, known, err := x86PackedWrappingAddProperties(ins, arch); known {
		return int64(form.memoryBytes), false, err == nil && !form.mmx && form.memory == index
	}
	if f, known, err := x86PackedConversionProperties(ins, arch); known {
		return int64(f.memoryBytes), false, err == nil && !f.mmx && f.memory == index
	}
	if f, known, err := x86SignedPackedFloatProperties(ins, arch); known {
		return int64(f.memoryBytes), false, err == nil && !f.mmx && f.memory == index
	}
	if form, recognized, err := x86PackedExtendProperties(ins, arch); recognized {
		return int64(form.memoryBytes), false, err == nil && form.memory == index &&
			(!form.signed || x86ResultNamedPredicateInstruction(ins))
	}
	if form, recognized, err := x86FloatCompareProperties(ins, arch); recognized {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if f, recognized, err := x86SignedIntegerFloatProperties(ins, arch); recognized {
		return int64(f.sourceBits / 8), false, err == nil && f.memory == index
	}
	if f, recognized, err := x86UnsignedIntegerFloatProperties(ins, arch); recognized {
		return int64(f.sourceBits / 8), false, err == nil && f.memory == index
	}
	if form, recognized, err := x86FloatArithmeticProperties(ins, arch, ""); recognized {
		return int64(form.memoryBytes), false, err == nil && form.memory == index
	}
	if f, recognized, err := x86InsertExtractProperties(ins, arch); recognized {
		return int64(f.spec.chunk), f.memoryWrite, err == nil && f.memory == index && !(f.mask >= 0 && f.memoryWrite)
	}
	if form, recognized, err := x86PackedShiftProperties(ins.Op, ins, arch); recognized {
		return int64(form.memoryBytes), false, err == nil && !form.mmx && form.memory == index
	}
	if form, recognized, err := x86HorizontalFloatProperties(ins, arch); recognized {
		return int64(form.byteWidth), false, err == nil && form.spec.vector && form.memory == index
	}
	if form, recognized, err := x86PackedUnpackProperties(ins, arch); recognized {
		return int64(form.memoryBytes), false, err == nil && !form.mmx && !form.legacy && form.memory == index
	}
	if form, recognized, err := x86PackedLogicalProperties(ins, arch); recognized {
		return int64(form.memoryBytes), false, err == nil && !form.mmx && form.memory == index
	}
	if width = x86RawReturnScalarMoveBytes(Op(normalizeInstructionOpcode(x86SourceMoveInstruction(ins, arch).Op))); width != 0 && len(ins.Args) == 2 {
		return width, index == 1, true
	}
	if form, recognized, err := x86ScalarExtensionProperties(ins.Op, ins, arch); recognized {
		return int64(form.spec.sourceBits / 8), false, err == nil && index == 0
	}
	if amd64MaskMoveOperandsValid(ins, arch) {
		return int64(amd64MaskMoveSpecs[ins.Op] / 8), index == 1, true
	}
	if form, recognized, err := amd64PackedVectorMoveProperties(ins, arch); recognized {
		return int64(form.byteWidth), form.memoryWrite, err == nil && !form.undefinedOpcode() && form.memory == index
	}
	if form, recognized, err := amd64FMA3Properties(ins, arch); recognized {
		return int64(form.memoryBytes), false, err == nil && !form.spec.rawOnly && form.memory == index
	}
	form, recognized, err := amd64ScalarVectorMoveProperties(ins, arch)
	if !recognized || err != nil || form.memory != index {
		return 0, false, false
	}
	return int64(form.spec.bits / 8), form.memoryWrite, true
}

func x86CallerPackedVectorMoveStep(ins *Instr, form amd64PackedVectorMoveForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.undefinedOpcode() || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	widthMask := x86CallerVectorByteMask(int64(form.byteWidth))
	var known uint64
	if form.memory >= 0 {
		// A slice-data/nonalias witness is not a SIMD alignment promise.
		// Aligned register copies are valid, but aligned memory requires a
		// separate actual-address proof before borrowing this continuation.
		if form.spec.aligned || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.byteWidth), form.memoryWrite) {
			return false
		}
		if form.memoryWrite {
			return state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)]&widthMask == widthMask
		}
		known = widthMask
	} else {
		known = state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)] & widthMask
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	// No initialized mask is assumed all-one. Both potential inputs matter.
	known = form.definedActiveBytes(known, state.vectors[destination])
	state.vectors[destination] = ^widthMask | known
	return true
}
