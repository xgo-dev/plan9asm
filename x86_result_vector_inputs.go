package plan9asm

// x86ResultApplyTypedVectorEffect evaluates a validated vector x86TypedByteEffect
// against x86ResultState. Memory and K-mask reads remain strict obligations;
// vectorLaneBytes==0 requires all vector register inputs strictly, while
// vectorLaneBytes>0 propagates defined bytes per lane (respecting laneReadMask,
// broadcast and masked mergeDestination). On any failure, state is untouched.
func x86ResultApplyTypedVectorEffect(ins Instr, effect x86TypedByteEffect,
	state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if x86Mode32VectorRegisterContext(ins, arch) != nil {
		return false
	}
	legacy := effect.vector.upperWrite == x86TypedVectorUpperPreserve
	destOpIdx := -1
	for index := range effect.operands {
		operand := &effect.operands[index]
		if operand.write {
			destOpIdx = index
		}
		if !operand.read {
			continue
		}
		if operand.operand.Kind == OpReg {
			if amd64IsKOperand(operand.operand) {
				mask, valid := amd64ParseKReg(operand.operand.Reg)
				if !valid || !state.masks[mask] {
					return false
				}
				continue
			}
			regWidth := amd64VectorByteWidth(operand.operand.Reg)
			if regWidth == 0 {
				return false // Non-vector/non-K register (e.g., MMX) stays outside this domain.
			}
			regIdx, valid := amd64VectorRegisterIndex(operand.operand.Reg, regWidth)
			if !valid || arch == "386" && regIdx >= 8 {
				return false
			}
			continue
		}
		if effect.requireLegacyNativeMemory && legacy {
			if operand.operand.Kind == OpFP || operand.operand.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(operand.operand, arch) {
				return false // Virtual bytes cannot supply original aligned legacy m128 backing.
			}
		}
		if !x86ResultReadWithNativeContinuation(ins, operand.operand, operand.width, state, owned, arch, nativeRead) {
			return false
		}
	}
	if destOpIdx < 0 || effect.operands[destOpIdx].operand.Kind != OpReg {
		return false
	}
	destOp := effect.operands[destOpIdx]
	destWidth := int(destOp.width)
	destIdx, valid := amd64VectorRegisterIndex(destOp.operand.Reg, destWidth)
	if !valid || arch == "386" && destIdx >= 8 {
		return false
	}
	if nativeRead && effect.requireLegacyOldDest {
		full := x86CallerVectorByteMask(int64(destWidth))
		if state.vectorBytes(destIdx)&full != full {
			return false
		}
	}
	var defined uint64
	if effect.vectorLaneBytes == 0 {
		for index := range effect.operands {
			operand := &effect.operands[index]
			if !operand.read || operand.operand.Kind != OpReg || amd64IsKOperand(operand.operand) {
				continue
			}
			required := operand.requiredBytes
			if required == 0 {
				required = x86CallerVectorByteMask(operand.width)
			}
			regIdx, _ := amd64VectorRegisterIndex(operand.operand.Reg, amd64VectorByteWidth(operand.operand.Reg))
			if required == 0 || state.vectorBytes(regIdx)&required != required {
				return false
			}
		}
		active := x86CallerVectorByteMask(int64(destWidth)) &^ destOp.preservedBytes
		defined = active | state.vectorBytes(destIdx)&destOp.preservedBytes
	} else {
		laneBytes := int(effect.vectorLaneBytes)
		fullLane := x86CallerVectorByteMask(int64(laneBytes))
		for offset := 0; offset < destWidth; offset += laneBytes {
			laneKnown := true
			for index := range effect.operands {
				operand := &effect.operands[index]
				if !operand.read || operand.operand.Kind != OpReg || amd64IsKOperand(operand.operand) || operand.laneReadMask == 0 {
					continue
				}
				regIdx, _ := amd64VectorRegisterIndex(operand.operand.Reg, amd64VectorByteWidth(operand.operand.Reg))
				laneOffset := uint(offset)
				if operand.broadcast {
					laneOffset = 0
				}
				required := uint64(operand.laneReadMask) << laneOffset
				if state.vectorBytes(regIdx)&required != required {
					laneKnown = false
					break
				}
			}
			if laneKnown {
				defined |= fullLane << uint(offset)
			}
		}
		if effect.mergeDestination {
			defined &= state.vectorBytes(destIdx)
		}
	}
	state.writeVector(destIdx, destWidth, defined, legacy)
	return true
}

// x86ResultTypedVectorEffectStep resolves one validated vector instruction form
// once and applies its shared x86TypedByteEffect to x86ResultState. Standalone
// queries pass nativeRead=false; paired lowering passes nativeRead=true.
func x86ResultTypedVectorEffectStep(ins Instr, state *x86ResultState, owned []bool,
	arch string, nativeRead, strictWordMultiply bool) (bool, bool) {
	if len(ins.Op) == 0 || ins.x86NumericalRead != nil {
		return false, false
	}
	switch ins.Op[0] {
	case 'P', 'p', 'V', 'v', 'G', 'g':
	default:
		return false, false
	}
	var operandBuf [5]x86TypedByteOperand

	// 1. IFMA (named and exact decoded raw).
	if form, known, err := x86IFMAProperties(ins.Op, ins, arch); known {
		if err != nil {
			return false, true
		}
		if !x86ResultNamedPredicateInstruction(ins) {
			if !nativeRead || !x86RawOrdinaryVectorSource(ins, arch) {
				return false, true
			}
			// Preserve the validated physical form; clearing local provenance
			// must not reparse mode32 masks under named operand limits.
			ins.x86Encoded, ins.x86SourceRaw = false, nil
		}
		effect, n := x86TypedIFMAEffectForFormInto(&operandBuf, ins, form)
		effect.operands = operandBuf[:n]
		return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
	}

	// 2. FMA3 (named, exact decoded raw, and RIP literal).
	if form, known, err := amd64FMA3Properties(ins, arch); known && !form.spec.rawOnly {
		if err != nil {
			return false, true
		}
		if !x86ResultNamedPredicateInstruction(ins) || ins.x86FMA3Encoding != x86RawFMA3Absent {
			if !x86RawFMA3LiteralForm(ins, arch) {
				if !nativeRead || !x86RawFMA3Source(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
		}
		effect, n := x86TypedFMA3EffectForFormInto(&operandBuf, ins, form)
		effect.operands = operandBuf[:n]
		return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
	}

	// 3. Ternary logic (named, exact decoded raw, and RIP literal).
	if form, known, err := x86TernaryLogicProperties(ins.Op, ins, arch); known {
		if err != nil {
			return false, true
		}
		if !x86ResultNamedPredicateInstruction(ins) {
			literal := state.loweredStaticReads != nil && x86RawTernaryLogicLiteralForm(ins, arch)
			if !literal && (!nativeRead || !x86RawTernaryLogicSource(ins, arch)) {
				return false, true
			}
			ins.x86Encoded, ins.x86SourceRaw = false, nil
		}
		effect, n := x86TypedTernaryLogicEffectForFormInto(&operandBuf, ins, form)
		effect.operands = operandBuf[:n]
		return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
	}

	// 4. Integer min/max (named, exact decoded raw, and RIP literal).
	if form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, arch); known {
		if err != nil || form.mmx {
			return false, true
		}
		if !x86ResultNamedPredicateInstruction(ins) {
			literal := state.loweredStaticReads != nil && x86RawIntegerMinMaxLiteralForm(ins, arch)
			if !literal && (!nativeRead || form.legacy || !ins.x86Encoded || !x86RawOrdinaryVectorSource(ins, arch)) {
				return false, true
			}
			ins.x86Encoded, ins.x86SourceRaw = false, nil
		}
		effect, n := x86PackedBinaryLaneEffectInto(&operandBuf, ins, form.x86PackedBinaryForm, uint8(form.spec.laneBits/8))
		if form.legacy && form.memory >= 0 {
			effect.requireLegacyNativeMemory = true
			effect.requireLegacyOldDest = true
		}
		effect.operands = operandBuf[:n]
		return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
	}

	// 5. Packed integer add/sub and D/Q low multiply.
	const packedArith = x86PackedArithmeticAdd | x86PackedArithmeticSubtract | x86PackedArithmeticLowMultiply
	if parsed, known, err := x86PackedArithmeticProperties(ins.Op, ins, arch, packedArith); known {
		if err != nil {
			return false, true
		}
		if parsed.spec.family != x86PackedArithmeticLowMultiply && parsed.legacy {
			return false, false // Legacy PADD/PSUB keep their dedicated typed/native consumers.
		}
		if parsed.mmx {
			return false, true
		}
		if nativeRead && parsed.spec.family == x86PackedArithmeticLowMultiply &&
			parsed.memory >= 0 && ins.Args[parsed.memory].Kind == OpMem {
			if !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			effect, n := x86PackedBinaryDependencyEffectInto(&operandBuf, ins, parsed.x86PackedBinaryForm, ins.Args[parsed.first])
			effect.operands = operandBuf[:n]
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, true), true
		}
		effect, n := x86PackedBinaryLaneEffectInto(&operandBuf, ins, parsed.x86PackedBinaryForm, uint8(parsed.spec.laneBits/8))
		effect.operands = operandBuf[:n]
		return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
	}

	// 6. Packed physical families (average, word multiply, multiply-add, dword product).
	if parsed, known, err := x86PackedPhysicalProperties(ins.Op, ins, arch, ""); known {
		if err != nil || parsed.mmx {
			return false, true
		}
		if !strictWordMultiply && parsed.spec.family == x86PackedWordProduct && parsed.spec.mode == amd64PackedWordMultiplyLow {
			// W/D/Q low products keep per-lane numerical dependencies in
			// standalone ABI0 queries (including decoded VPMULLW); lowering
			// retains strict whole-vector and named-source checks below.
			effect, n := x86PackedBinaryLaneEffectInto(&operandBuf, ins, parsed.x86PackedBinaryForm, 2)
			effect.operands = operandBuf[:n]
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		if !x86ResultNamedPredicateInstruction(ins) {
			if !nativeRead || parsed.spec.family != x86PackedDwordProduct || parsed.legacy ||
				!x86RawOrdinaryVectorSource(ins, arch) {
				return false, true
			}
			ins.x86Encoded, ins.x86SourceRaw = false, nil
		}
		effect, n := x86PackedBinaryDependencyEffectInto(&operandBuf, ins, parsed.x86PackedBinaryForm, ins.Args[parsed.first])
		effect.operands = operandBuf[:n]
		return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
	}

	// 7. Remaining fixed-vector PackedBinary families (blocks, rotate, conflict,
	// funnel, horizontal, indexed permute, GFNI, bit count).
	if form, oldInput, known, err := x86OtherFixedVectorValueProperties(ins, arch); known {
		if err != nil || form.mmx || !x86ResultNamedPredicateInstruction(ins) {
			return false, true
		}
		effect, n := x86TypedFixedVectorInputsInto(&operandBuf, ins, form, oldInput)
		if form.legacy {
			effect.vector = x86TypedVectorEffect{upperWrite: x86TypedVectorUpperPreserve, memoryAlignment: int64(form.byteWidth)}
		}
		effect.operands = operandBuf[:n]
		return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
	}
	return false, false
}

// Share only the complete family grammar and old-destination input role.
// This description grants no numerical, memory, frame or declaration authority.
func x86FixedVectorValueProperties(ins Instr, arch string) (x86PackedBinaryForm, bool, bool, error) {
	if parsed, known, err := x86PackedPhysicalProperties(ins.Op, ins, arch, ""); known {
		return parsed.x86PackedBinaryForm, false, known, err
	}
	if form, known, err := x86IFMAProperties(ins.Op, ins, arch); known {
		return form.x86PackedBinaryForm, true, true, err
	}
	return x86OtherFixedVectorValueProperties(ins, arch)
}

func x86OtherFixedVectorValueProperties(ins Instr, arch string) (x86PackedBinaryForm, bool, bool, error) {
	if parsed, known, err := x86Shuffle128BitBlocksProperties(ins.Op, ins, arch); known {
		return parsed.x86PackedBinaryForm, false, known, err
	}
	if parsed, known, err := x86PackedRotateProperties(ins.Op, ins, arch); known {
		return parsed.x86PackedBinaryForm, false, known, err
	}
	if parsed, known, err := x86PackedConflictProperties(ins.Op, ins, arch); known {
		return parsed.x86PackedBinaryForm, false, known, err
	}
	if parsed, known, err := x86FunnelShiftProperties(ins.Op, ins, arch); known {
		return parsed.x86PackedBinaryForm, parsed.spec.variable, known, err
	}
	if parsed, known, err := x86HorizontalIntegerProperties(ins, arch); known {
		memoryBytes := 0
		if parsed.memory >= 0 {
			memoryBytes = parsed.byteWidth
		}
		return x86PackedBinaryForm{
			first: parsed.first, second: parsed.second, destination: parsed.destination,
			memory: parsed.memory, memoryBytes: memoryBytes, byteWidth: parsed.byteWidth,
			mask: -1, legacy: !parsed.spec.vector, mmx: parsed.mmx,
		}, false, true, err
	}
	if parsed, spec, recognized, parseErr := x86IndexedPermuteProperties(ins.Op, ins, arch); recognized {
		return parsed, spec.readsOldDestination(), recognized, parseErr
	}
	if parsed, recognized, parseErr := x86GFNIProperties(ins.Op, ins, arch); recognized {
		return parsed.x86PackedBinaryForm, false, recognized, parseErr
	}
	if parsed, recognized, parseErr := x86PackedBitCountProperties(ins.Op, ins, arch); recognized {
		return parsed.x86PackedBinaryForm, false, recognized, parseErr
	}
	return x86PackedBinaryForm{}, false, false, nil
}

// This is only a numerical vector view. Keep the older scalar/legacy-X read
// domain unchanged; neither native pointers nor wider logical storage follow.
func x86ResultPackedVectorRead(operand Operand, width int64, state *x86ResultState, owned []bool, arch string) bool {
	if operand.Kind != OpReg {
		return x86ResultRead(operand, width, state, owned, arch)
	}
	index, valid := amd64VectorRegisterIndex(operand.Reg, int(width))
	mask := x86CallerVectorByteMask(width)
	return valid && (arch != "386" || index < 8) && mask != 0 && state.vectorBytes(index)&mask == mask
}
