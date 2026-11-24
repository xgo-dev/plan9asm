package plan9asm

// x86ResultApplyTypedVectorEffect evaluates a validated vector x86TypedByteEffect
// against x86ResultState. Memory and K-mask reads remain strict obligations;
// vectorLaneBytes==0 requires all vector register inputs strictly (unless
// softRegisterInputs clears active bytes instead), while vectorLaneBytes>0
// propagates defined bytes per lane. K-mask destinations define state.masks.
// On any failure, state is untouched.
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
			if _, static := x86StaticSBReadAddress(operand.operand, arch); !static &&
				(operand.operand.Kind == OpFP || !nativeRead || !x86OrdinaryNativeMemoryOperand(operand.operand, arch)) {
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
	if amd64IsKOperand(destOp.operand) {
		destMask, valid := amd64ParseKReg(destOp.operand.Reg)
		if !valid {
			return false
		}
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
		state.masks[destMask] = true
		return true
	}
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
		active := x86CallerVectorByteMask(int64(destWidth)) &^ destOp.preservedBytes
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
				if !effect.softRegisterInputs {
					return false
				}
				active = 0
			}
		}
		preservedSource := destIdx
		if effect.preservedFromOperand > 0 {
			srcOp := effect.operands[effect.preservedFromOperand-1].operand
			var validSrc bool
			preservedSource, validSrc = amd64VectorRegisterIndex(srcOp.Reg, amd64VectorByteWidth(srcOp.Reg))
			if !validSrc || arch == "386" && preservedSource >= 8 {
				return false
			}
		}
		defined = active | state.vectorBytes(preservedSource)&destOp.preservedBytes
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

func x86ResultCheckKMask(ins Instr, maskIdx int, state *x86ResultState) bool {
	if maskIdx < 0 {
		return true
	}
	mask, valid := amd64ParseKReg(ins.Args[maskIdx].Reg)
	return valid && state.masks[mask]
}

// x86ResultReadVectorSourceMask reads a vector source operand (memory or register)
// into a defined-byte bitmask. Memory reads are strict (returning false on failure).
func x86ResultReadVectorSourceMask(ins Instr, source Operand, isMem bool, regWidth, memBytes, resultMaskWidth int,
	state *x86ResultState, owned []bool, arch string, nativeRead bool) (uint64, bool) {
	if isMem {
		if !x86ResultReadWithNativeContinuation(ins, source, int64(memBytes), state, owned, arch, nativeRead) {
			return 0, false
		}
		return x86CallerVectorByteMask(int64(resultMaskWidth)), true
	}
	index, valid := amd64VectorRegisterIndex(source.Reg, regWidth)
	if !valid || arch == "386" && index >= 8 {
		return 0, false
	}
	return state.vectorBytes(index), true
}

func x86ResultVectorUpperWrite(legacy bool) x86TypedVectorEffect {
	if legacy {
		return x86TypedVectorEffect{upperWrite: x86TypedVectorUpperPreserve, memoryAlignment: 16}
	}
	return x86TypedVectorEffect{upperWrite: x86TypedVectorUpperZero, memoryAlignment: 1}
}

// x86ResultTypedVectorEffectStep resolves one validated vector instruction form
// and evaluates its shared x86TypedByteEffect (or byte-level transfer) against
// x86ResultState. Standalone queries pass nativeRead=false; paired lowering
// passes nativeRead=true. strictWordMultiply selects lowering/scalar-FP semantics
// (whole-vector word multiply and float min/max).
func x86ResultTypedVectorEffectStep(ins Instr, state *x86ResultState, owned []bool,
	arch string, nativeRead, strictWordMultiply bool) (bool, bool) {
	if len(ins.Op) == 0 || ins.x86NumericalRead != nil {
		return false, false
	}
	op0 := ins.Op[0]
	if op0 >= 'a' && op0 <= 'z' {
		op0 -= 'a' - 'A'
	}
	switch op0 {
	case 'A', 'B', 'C', 'D', 'G', 'H', 'M', 'P', 'R', 'S', 'U', 'V':
	default:
		return false, false
	}
	var operandBuf [5]x86TypedByteOperand

	// Shared families routed by leading mnemonic character to avoid probing
	// unrelated instruction tables on every CFG transfer.
	switch op0 {
	case 'A', 'V':
		if form, known, err := x86AlternatingFloatProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			local := ins
			if !x86ResultNamedPredicateInstruction(local) {
				if !nativeRead || !x86RawAlternatingFloatSource(ins, arch) {
					return false, true
				}
				local.x86Encoded, local.x86SourceRaw = false, nil
			}
			read := nativeRead && (!form.legacy || form.memory >= 0 &&
				x86LegacyAlternatingRoundMemorySource(local, local.Args[form.first], arch))
			return x86ScalarFPFloatBinaryTransferWithRead(local, form, state, owned, arch, read), true
		}
		if f, known, err := x86AESProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawAESSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			read := func(index int) (uint64, bool) {
				a := ins.Args[index]
				if index == f.source {
					a = f.sourceOperand
				}
				if a.Kind == OpReg {
					i, valid := amd64VectorRegisterIndex(a.Reg, f.byteWidth)
					if !valid || i >= len(state.xmm) {
						return 0, false
					}
					return state.vectorBytes(i), true
				}
				return x86CallerVectorByteMask(int64(f.byteWidth)),
					x86ResultReadWithNativeContinuation(ins, a, int64(f.byteWidth), state, owned, arch, nativeRead && index == f.source)
			}
			source, valid := read(f.source)
			if !valid {
				return false, true
			}
			input := uint64(0)
			if f.state >= 0 {
				input, valid = read(f.state)
				if !valid {
					return false, true
				}
			}
			destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
			if destination >= len(state.xmm) {
				return false, true
			}
			state.writeVector(destination, f.byteWidth, x86AESDefinedBytes(f, source, input), !f.spec.vector)
			return true, true
		}
	}

	switch op0 {
	case 'B', 'P', 'V':
		if f, known, err := x86ImmediateBlendProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			local := ins
			if !x86ResultNamedPredicateInstruction(local) {
				if !nativeRead || !x86RawImmediateBlendSource(ins, arch) {
					return false, true
				}
				local.x86Encoded, local.x86SourceRaw = false, nil
			}
			first, ok := x86ResultReadVectorSourceMask(local, ins.Args[f.source], f.memory,
				f.byteWidth, f.byteWidth, f.byteWidth, state, owned, arch, nativeRead)
			if !ok {
				return false, true
			}
			baseIndex, _ := amd64VectorRegisterIndex(ins.Args[f.base].Reg, f.byteWidth)
			base := state.vectorBytes(baseIndex)
			var defined uint64
			for output := 0; output < f.byteWidth; output++ {
				source := base
				if f.selectsFirst(output) {
					source = first
				}
				defined |= (source >> uint(output) & 1) << uint(output)
			}
			destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
			state.writeVector(destination, f.byteWidth, defined, f.legacy)
			return true, true
		}
		if form, known, err := x86BlendMinposProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			local := ins
			if !x86ResultNamedPredicateInstruction(local) {
				if !nativeRead || !x86RawBlendMinposSource(ins, arch) {
					return false, true
				}
				local.x86Encoded, local.x86SourceRaw = false, nil
			}
			source, ok := x86ResultReadVectorSourceMask(local, ins.Args[form.source], form.memory,
				form.byteWidth, form.byteWidth, form.byteWidth, state, owned, arch, nativeRead)
			if !ok {
				return false, true
			}
			var initialized uint64
			if form.minimum {
				initialized = 0xfff8 // Clears bits 127:19 independently of input values.
				if source&0xffff == 0xffff {
					initialized |= 7
				}
			} else {
				maskIndex, _ := amd64VectorRegisterIndex(ins.Args[form.mask].Reg, form.byteWidth)
				baseIndex, _ := amd64VectorRegisterIndex(ins.Args[form.base].Reg, form.byteWidth)
				mask, base := state.vectorBytes(maskIndex), state.vectorBytes(baseIndex)
				laneBytes := form.laneBits / 8
				for at := 0; at < form.byteWidth; at++ {
					flag := uint((at/laneBytes+1)*laneBytes - 1)
					bit := uint64(1) << uint(at)
					if mask&(uint64(1)<<flag) != 0 && source&bit != 0 && base&bit != 0 {
						initialized |= bit
					}
				}
			}
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
			state.writeVector(destination, form.byteWidth, initialized, form.legacy)
			return true, true
		}
	}

	switch op0 {
	case 'C', 'U', 'V':
		// Scalar float comparisons to FLAGS (COMISS/SD, UCOMISS/SD, V*COMI*).
		if form, known, err := x86COMIProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) && !ins.x86RIPLiteral {
				if !nativeRead || !form.spec.vector || !x86RawCOMISource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			width := int64(form.spec.bits / 8)
			for _, operand := range ins.Args {
				if operand.Kind == OpReg {
					index, _ := amd64ParseXReg(operand.Reg)
					mask := x86CallerVectorByteMask(width)
					if state.vectorBytes(index)&mask != mask {
						return false, true
					}
				} else if !x86ResultReadWithNativeContinuation(ins, operand, width, state, owned, arch, nativeRead) {
					return false, true
				}
			}
			state.flags = x86ByteFlagsAll
			return true, true
		}
	}

	switch op0 {
	case 'C', 'V':
		// Scalar float -> GP integer conversions (CVTS*2SI, VCVTS*2SI/USI).
		if f, known, err := x86ScalarFloatIntegerProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			if nativeRead && !x86ResultNamedPredicateInstruction(ins) {
				if !x86RawScalarFloatIntegerSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			width := int64(f.spec.inputBits / 8)
			source := ins.Args[0]
			if source.Kind == OpReg {
				index, _ := amd64ParseXReg(source.Reg)
				mask := x86CallerVectorByteMask(width)
				if state.vectorBytes(index)&mask != mask {
					return false, true
				}
			} else if !x86ResultReadWithNativeContinuation(ins, source, width, state, owned, arch, nativeRead) {
				return false, true
			}
			return x86ResultStore(ins.Args[1], int64(f.outputBits/8), state, owned, 0, arch), true
		}
		// Scalar precision conversions (CVTSS2SD, CVTSD2SS, VCVTSS2SD, VCVTSD2SS).
		if form, known, err := x86ScalarPrecisionProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawScalarPrecisionSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			inputBytes := int64(form.spec.inputBits / 8)
			outputMask := x86CallerVectorByteMask(int64(form.spec.outputBits / 8))
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[0], width: inputBytes, read: true, requiredBytes: x86CallerVectorByteMask(inputBytes)}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[form.second], width: 16}
			operandBuf[2] = x86TypedByteOperand{
				operand: ins.Args[form.destination], width: 16, write: true,
				read: form.mask >= 0 && !form.zeroing, requiredBytes: outputMask,
				preservedBytes: 0xffff &^ outputMask,
			}
			n := 3
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{
				operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(form.legacy),
				preservedFromOperand: 2, // second operand supplies upper bytes
			}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// Packed precision conversions (CVTPS2PD, CVTPD2PS, VCVTPS2PD, VCVTPD2PS*).
		if form, known, err := x86PackedPrecisionProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawPackedPrecisionSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			return x86ResultPackedConversionInputs(ins, form, state, owned, arch, nativeRead), true
		}
		// Signed packed integer <-> float conversions (CVTDQ2PS, VCVTDQ2PS, ...).
		if form, known, err := x86SignedPackedFloatProperties(ins, arch); known {
			if err != nil || form.mmx {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawPackedConversionSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			srcWidth := int64(form.sourceBytes)
			if ins.Args[0].Kind != OpReg {
				srcWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{
				operand: ins.Args[0], width: srcWidth, read: true,
				requiredBytes: x86CallerVectorByteMask(int64(form.inputBytes)),
			}
			operandBuf[1] = x86TypedByteOperand{
				operand: ins.Args[form.destination], width: int64(form.byteWidth),
				read: form.mask >= 0 && !form.zeroing, write: true,
			}
			n := 2
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(form.spec.legacy)}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// Packed numeric float <-> integer conversions (CVTPS2DQ, ...).
		if form, known, err := x86PackedConversionProperties(ins, arch); known {
			if err != nil || form.mmx {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawPackedConversionSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			return x86ResultPackedConversionInputs(ins, form, state, owned, arch, nativeRead), true
		}
	}

	switch op0 {
	case 'D', 'H', 'V':
		if form, known, err := x86PackedReductionProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawPackedReductionSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			if form.legacy && form.memory >= 0 && ins.Args[form.memory].Kind == OpFP {
				return false, true
			}
			required := form.inputBytes()
			width := int64(form.byteWidth)
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[form.first], width: width, read: required != 0 || form.first == form.memory, requiredBytes: required}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[form.second], width: width, read: required != 0 || form.second == form.memory, requiredBytes: required}
			operandBuf[2] = x86TypedByteOperand{operand: ins.Args[form.destination], width: width, write: true}
			effect := x86TypedByteEffect{operands: operandBuf[:3], vector: x86ResultVectorUpperWrite(form.legacy)}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
	}

	switch op0 {
	case 'M', 'V':
		if form, known, err := x86DuplicateMoveProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			srcWidth := int64(form.byteWidth)
			if form.memory >= 0 {
				srcWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: form.source, width: srcWidth, read: true, requiredBytes: form.sourceMask()}
			operandBuf[1] = x86TypedByteOperand{
				operand: ins.Args[form.destination], width: int64(form.byteWidth),
				read: form.mask >= 0 && !form.zeroing, write: true,
			}
			n := 2
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{
				operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(form.legacy),
				requireLegacyNativeMemory: form.legacy && form.spec.laneBytes == 4,
			}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
	}

	switch op0 {
	case 'M', 'P', 'V':
		if form, known, err := x86PackedSADProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultCheckKMask(ins, form.mask, state) {
				return false, true
			}
			width := x86CallerVectorByteMask(int64(form.byteWidth))
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
			if form.constantZero(ins) {
				state.writeVector(destination, form.byteWidth, width, form.legacy)
				return true, true
			}
			var requiredFirst, requiredSecond uint64
			for output := 0; output < form.byteWidth; output += 2 {
				first, second := form.wordInputs(output)
				requiredFirst |= first
				requiredSecond |= second
			}
			firstWidth := int64(form.byteWidth)
			if form.memory >= 0 {
				firstWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[form.first], width: firstWidth, read: true, requiredBytes: requiredFirst}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[form.second], width: int64(form.byteWidth), read: true, requiredBytes: requiredSecond}
			operandBuf[2] = x86TypedByteOperand{
				operand: ins.Args[form.destination], width: int64(form.byteWidth),
				read: form.mask >= 0 && !form.zeroing, write: true,
			}
			n := 3
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{
				operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(form.legacy),
				requireLegacyNativeMemory: form.legacy && form.memory >= 0,
			}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
	}

	if strictWordMultiply && (op0 == 'M' || op0 == 'V') {
		if f, known, err := x86FloatMinMaxProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) && !x86RawBinaryFloatLiteralForm(ins, arch) {
				if !nativeRead || !x86RawFloatMinMaxSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			return x86ScalarFPFloatBinaryTransferWithRead(ins, f.x86FloatBinaryForm, state, owned, arch, nativeRead), true
		}
	}

	switch op0 {
	case 'R', 'V':
		if form, known, err := x86RoundProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			literal := x86RawRoundLiteralForm(ins, arch)
			if !x86ResultNamedPredicateInstruction(ins) && !literal || !x86ResultRead(ins.Args[0], 1, state, owned, arch) {
				return false, true
			}
			low := x86CallerVectorByteMask(int64(form.memoryBytes))
			srcWidth := int64(form.byteWidth)
			if form.memory {
				srcWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: form.source, width: srcWidth, read: true, requiredBytes: low}
			operandBuf[1] = x86TypedByteOperand{operand: form.destination, width: int64(form.byteWidth), write: true}
			n := 2
			var preservedFrom int8
			if form.spec.scalar {
				upperRequired := uint64(0xffff) &^ low
				operandBuf[1].preservedBytes = upperRequired
				operandBuf[2] = x86TypedByteOperand{
					operand: form.upper, width: 16, read: literal, requiredBytes: upperRequired,
				}
				n = 3
				preservedFrom = 3
			}
			effect := x86TypedByteEffect{
				operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(!form.spec.vector),
				preservedFromOperand: preservedFrom,
			}
			read := nativeRead && (form.spec.vector || x86LegacyAlternatingRoundMemorySource(ins, form.source, arch))
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, read), true
		}
		if form, known, err := x86ScalarReciprocalProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawScalarReciprocalSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[0], width: 4, read: true, requiredBytes: 0xf}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[form.base], width: 16}
			operandBuf[2] = x86TypedByteOperand{operand: ins.Args[form.destination], width: 16, write: true, preservedBytes: 0xfff0}
			effect := x86TypedByteEffect{
				operands: operandBuf[:3], vector: x86ResultVectorUpperWrite(!form.spec.vector),
				softRegisterInputs: true, preservedFromOperand: 2,
			}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		if form, known, err := x86PackedReciprocalProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			width := int64(form.byteWidth)
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[0], width: width, read: true}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[1], width: width, write: true}
			effect := x86TypedByteEffect{
				operands: operandBuf[:2], vector: x86ResultVectorUpperWrite(form.legacy),
				requireLegacyNativeMemory: form.legacy, softRegisterInputs: true,
			}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
	}

	switch op0 {
	case 'S':
		if f, known, err := x86SHAProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !x86RawOrdinaryVectorSourceAt(ins, arch, f.source) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			input := uint64(0xffff)
			if f.memory >= 0 {
				if !x86ResultReadWithNativeContinuation(ins, f.sourceOperand, 16, state, owned, arch, nativeRead) {
					return false, true
				}
			} else {
				index, _ := amd64ParseXReg(f.sourceOperand.Reg)
				input = state.vectorBytes(index)
			}
			destination, _ := amd64ParseXReg(ins.Args[f.destination].Reg)
			defined := x86SHADefinedBytes(f, input, state.vectorBytes(destination), state.vectorBytes(0))
			state.writeVector(destination, 16, defined, true)
			return true, true
		}
	}

	switch op0 {
	case 'S', 'V':
		if f, known, err := x86SqrtProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			if f.bits == 16 {
				if !nativeRead || !x86RawFP16SqrtSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			if !x86ResultCheckKMask(ins, f.mask, state) {
				return false, true
			}
			input := ^uint64(0)
			if f.memory >= 0 {
				if !f.scalar && ins.Args[0].Kind == OpFP {
					return false, true
				}
				if !x86ResultReadWithNativeContinuation(ins, ins.Args[0], int64(f.memoryBytes), state, owned, arch, nativeRead) {
					return false, true
				}
			} else {
				source, _ := amd64VectorRegisterIndex(ins.Args[0].Reg, f.byteWidth)
				input = state.vectorBytes(source)
			}
			destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
			upper, _ := amd64VectorRegisterIndex(ins.Args[f.second].Reg, f.byteWidth)
			value, valid := x86SqrtDefinedBytes(f, input, state.vectorBytes(upper), state.vectorBytes(destination))
			if !valid {
				return false, true
			}
			state.writeVector(destination, f.byteWidth, value, f.legacy)
			return true, true
		}
		if f, known, err := x86PackedFloatShuffleProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			if !x86ResultCheckKMask(ins, f.mask, state) {
				return false, true
			}
			if f.memory >= 0 && f.legacy && ins.Args[f.first].Kind == OpFP {
				return false, true
			}
			first, ok := x86ResultReadVectorSourceMask(ins, ins.Args[f.first], f.memory >= 0,
				f.byteWidth, f.memoryBytes, f.memoryBytes, state, owned, arch, nativeRead)
			if !ok {
				return false, true
			}
			second, _ := amd64VectorRegisterIndex(ins.Args[f.second].Reg, f.byteWidth)
			destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
			defined := f.definedBytes(first, state.vectorBytes(second), state.vectorBytes(destination))
			if f.memory >= 0 && nativeRead && defined != x86CallerVectorByteMask(int64(f.byteWidth)) {
				return false, true // Dead native reads cannot invent selected/merging input bytes.
			}
			state.writeVector(destination, f.byteWidth, defined, f.legacy)
			return true, true
		}
	}

	switch op0 {
	case 'U', 'P', 'V':
		if form, known, err := x86PackedUnpackProperties(ins, arch); known {
			if err != nil || form.mmx {
				return false, true
			}
			if !x86ResultCheckKMask(ins, form.mask, state) {
				return false, true
			}
			var first uint64
			if form.memory >= 0 {
				if _, static := x86StaticSBReadAddress(form.source, arch); form.legacy && !static &&
					(!nativeRead || !x86OrdinaryNativeMemoryOperand(form.source, arch)) {
					return false, true
				}
				if !x86ResultReadWithNativeContinuation(ins, form.source, int64(form.memoryBytes), state, owned, arch, nativeRead) {
					return false, true
				}
				first = x86CallerVectorByteMask(int64(form.byteWidth))
			} else {
				index, _ := amd64VectorRegisterIndex(ins.Args[form.first].Reg, form.byteWidth)
				first = state.vectorBytes(index)
			}
			second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
			defined := x86PackedUnpackDefinedBytes(form, first, state.vectorBytes(second), state.vectorBytes(destination))
			state.writeVector(destination, form.byteWidth, defined, form.legacy)
			return true, true
		}
	}

	if op0 == 'P' || op0 == 'V' {
		if form, known, err := x86PackedNarrowProperties(ins, arch); known {
			if err != nil || form.mmx {
				return false, true
			}
			if !x86ResultCheckKMask(ins, form.mask, state) {
				return false, true
			}
			var first uint64
			if form.memory >= 0 {
				_, static := x86StaticSBReadAddress(form.source, arch)
				if form.legacy && !static && !nativeRead {
					return false, true
				}
				if !x86ResultReadWithNativeContinuation(ins, form.source, int64(form.memoryBytes), state, owned, arch, nativeRead) {
					return false, true
				}
				first = x86CallerVectorByteMask(int64(form.byteWidth))
			} else {
				index, _ := amd64VectorRegisterIndex(ins.Args[form.first].Reg, form.byteWidth)
				first = state.vectorBytes(index)
			}
			second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
			defined := x86PackedNarrowDefinedBytes(form, first, state.vectorBytes(second), state.vectorBytes(destination))
			state.writeVector(destination, form.byteWidth, defined, form.legacy)
			return true, true
		}
		if form, known, err := x86PackedAbsSignProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) && !x86RawPackedAbsLiteralForm(ins, arch) {
				return false, true
			}
			laneBytes := uint8(form.spec.laneBits / 8)
			laneMask := uint8(x86CallerVectorByteMask(int64(laneBytes)))
			firstWidth := int64(form.byteWidth)
			if form.memory >= 0 {
				firstWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[form.first], width: firstWidth, read: true, laneReadMask: laneMask, broadcast: form.broadcast}
			n := 1
			if form.spec.sign {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.second], width: int64(form.byteWidth), read: true, laneReadMask: laneMask}
				n++
			}
			operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true}
			n++
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{
				operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(form.legacy),
				vectorLaneBytes: laneBytes, mergeDestination: form.mask >= 0 && !form.zeroing,
			}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		if form, known, err := x86PackedAlignProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			if !x86ResultCheckKMask(ins, form.mask, state) {
				return false, true
			}
			if form.memory >= 0 && form.legacy && ins.Args[form.first].Kind == OpFP {
				return false, true
			}
			first, ok := x86ResultReadVectorSourceMask(ins, ins.Args[form.first], form.memory >= 0,
				form.byteWidth, form.memoryBytes, form.byteWidth, state, owned, arch, nativeRead)
			if !ok {
				return false, true
			}
			second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
			defined := form.definedBytes(first, state.vectorBytes(second), state.vectorBytes(destination))
			state.writeVector(destination, form.byteWidth, defined, form.legacy)
			return true, true
		}
		// Packed zero/sign extend (PMOVZX*, PMOVSX*, VPMOVZX*, VPMOVSX*).
		if form, known, err := x86PackedZeroExtendProperties(ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawZeroExtendSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			return x86ResultPackedExtendTransfer(ins, form, state, owned, arch, nativeRead), true
		}
		if form, known, err := x86PackedSignExtendProperties(ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			return x86ResultPackedExtendTransfer(ins, form, state, owned, arch, nativeRead), true
		}
		// Byte shuffle (PSHUFB, VPSHUFB).
		if form, known, err := x86ByteShuffleProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultCheckKMask(ins, form.mask, state) {
				return false, true
			}
			control, ok := x86ResultReadVectorSourceMask(ins, ins.Args[form.first], form.memory >= 0,
				form.byteWidth, form.memoryBytes, form.byteWidth, state, owned, arch, nativeRead)
			if !ok {
				return false, true
			}
			data, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, form.byteWidth)
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
			initialized := x86ByteShuffleDefinedBytes(form.byteWidth, control, state.vectorBytes(data))
			if form.mask >= 0 && !form.zeroing {
				initialized &= state.vectorBytes(destination)
			}
			state.writeVector(destination, form.byteWidth, initialized, form.legacy)
			return true, true
		}
		// Immediate shuffle (PSHUFD/HW/LW, VPSHUF*).
		if form, known, err := x86ImmediateShuffleProperties(ins, arch); known {
			if err != nil || form.spec.mmx {
				return false, true
			}
			if !x86ResultCheckKMask(ins, form.mask, state) {
				return false, true
			}
			if form.memory >= 0 {
				if _, static := x86StaticSBReadAddress(form.source, arch); form.spec.legacy && !static &&
					(!nativeRead || !x86OrdinaryNativeMemoryOperand(form.source, arch)) {
					return false, true
				}
			}
			source, ok := x86ResultReadVectorSourceMask(ins, form.source, form.memory >= 0,
				form.byteWidth, form.memoryBytes, form.memoryBytes, state, owned, arch, nativeRead)
			if !ok {
				return false, true
			}
			var defined uint64
			for output := 0; output < form.byteWidth; output++ {
				defined |= (source >> uint(form.sourceByte(output)) & 1) << uint(output)
			}
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
			if form.mask >= 0 && !form.zeroing {
				defined &= state.vectorBytes(destination)
			}
			state.writeVector(destination, form.byteWidth, defined, form.spec.legacy)
			return true, true
		}
		// Vector test (PTEST, VPTEST, VTESTPS, VTESTPD).
		if form, known, err := x86VectorTestProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawVectorTestSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			for role, operand := range ins.Args {
				if operand.Kind != OpReg {
					if !nativeRead || role != 0 || !x86ResultReadWithNativeContinuation(ins, operand,
						int64(form.byteWidth), state, owned, arch, true) {
						return false, true
					}
					continue
				}
				index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
				mask := x86CallerVectorByteMask(int64(form.byteWidth))
				if !valid || arch == "386" && index >= 8 || state.vectorBytes(index)&mask != mask {
					return false, true
				}
			}
			state.flags = x86ByteFlagsAll
			return true, true
		}
		// Packed integer compare (PCMPEQ*, PCMPGT*, VPCMP*).
		if form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch); known {
			if err != nil || form.mmx {
				return false, true
			}
			if nativeRead && !x86ResultNamedPredicateInstruction(ins) {
				if !x86RawPackedIntegerCompareSource(ins, arch) {
					return false, true
				}
				local := ins
				local.x86Encoded, local.x86SourceRaw = false, nil
				return x86ResultVectorCompareTransfer(local, form, state, owned, arch, true)
			}
			if nativeRead && !form.maskResult && form.mask < 0 && x86ResultNamedPredicateInstruction(ins) {
				return x86ResultNamedCompareLaneTransfer(ins, form, state, owned, arch)
			}
			return x86ResultVectorCompareTransfer(ins, form, state, owned, arch, nativeRead)
		}
		if immForm, known, err := x86ImmediatePackedCompareProperties(ins.Op, ins, arch); known {
			if err != nil || immForm.mmx {
				return false, true
			}
			if nativeRead && !x86ResultNamedPredicateInstruction(ins) {
				if !x86RawImmediatePackedCompareSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			return x86ResultVectorCompareTransfer(ins, immForm.x86PackedIntegerCompareForm, state, owned, arch, nativeRead)
		}
		// Packed shift (PSLL*, PSRL*, PSRA*, VPSLL*, VPSRL*, VPSRA*).
		if form, known, err := x86PackedShiftProperties(ins.Op, ins, arch); known {
			if err != nil || form.mmx {
				return false, true
			}
			literal := x86RawByteShiftLiteralForm(ins, arch)
			if !literal && !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawPackedShiftSource(ins, arch) {
					return false, true
				}
				local := ins
				local.x86Encoded, local.x86SourceRaw = false, nil
				local.x86PackedShiftEncoding, local.x86PackedShiftW = x86RawPackedShiftAbsent, false
				return x86ResultPackedShiftInputs(local, form, state, owned, arch, true), true
			}
			if !literal && (ins.x86PackedShiftEncoding != x86RawPackedShiftAbsent || ins.x86PackedShiftW) {
				return false, true
			}
			var pending x86ResultShiftBits
			if nativeRead && ins.Args[form.data].Kind == OpReg {
				input, _ := amd64VectorRegisterIndex(ins.Args[form.data].Reg, form.byteWidth)
				destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
				pending = x86ResultShiftBitSource(ins, form, state.vectorBytes(input), destination)
			}
			if !x86ResultPackedShiftInputs(ins, form, state, owned, arch, nativeRead) {
				return false, true
			}
			if nativeRead {
				state.shiftBits = pending
			}
			return true, true
		}
		// Carryless multiply (PCLMULQDQ, VPCLMULQDQ).
		if f, known, err := x86CLMULProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			local := ins
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawCLMULSource(ins, arch) {
					return false, true
				}
				local.x86Encoded, local.x86SourceRaw = false, nil
			}
			source := x86CallerVectorByteMask(int64(f.byteWidth))
			if f.memory >= 0 {
				if !x86ResultReadWithNativeContinuation(local, local.Args[f.memory], int64(f.byteWidth), state, owned, arch, nativeRead) {
					return false, true
				}
			} else {
				index, _ := amd64VectorRegisterIndex(local.Args[f.source].Reg, f.byteWidth)
				source = state.vectorBytes(index)
			}
			second, _ := amd64VectorRegisterIndex(local.Args[f.second].Reg, f.byteWidth)
			destination, _ := amd64VectorRegisterIndex(local.Args[f.destination].Reg, f.byteWidth)
			state.writeVector(destination, f.byteWidth, x86CLMULDefinedBytes(f, source, state.vectorBytes(second)), f.legacy)
			return true, true
		}
	}

	// VEX/EVEX-only families (all start with 'V').
	if op0 == 'V' {
		// Packed test to K-mask (VPTESTM*, VPTESTNM*).
		if f, known, err := x86PackedTestMaskProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			firstWidth, secondWidth := int64(f.byteWidth), int64(f.byteWidth)
			if f.memory == f.first {
				firstWidth = int64(f.memoryBytes)
			} else if f.memory == f.second {
				secondWidth = int64(f.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[f.first], width: firstWidth, read: true}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[f.second], width: secondWidth, read: true}
			operandBuf[2] = x86TypedByteOperand{operand: ins.Args[f.destination], width: 8, write: true}
			n := 3
			if f.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[f.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(false)}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// Scalar, block and K-data broadcasts (VPBROADCAST*, VBROADCAST*).
		if f, known, err := x86BroadcastProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			local := ins
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawBroadcastSource(ins, arch) {
					return false, true
				}
				local.x86Encoded, local.x86SourceRaw = false, nil
			}
			return x86ResultBroadcastTransfer(local, f, state, owned, arch, nativeRead, false)
		}
		// Named half-precision conversions (VCVTPH2PS, VCVTPS2PH).
		if f, known, err := x86NamedHalfProperties(ins.Op, ins, arch); known {
			if err != nil || f.undefinedOpcode() {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawNamedHalfSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			local := ins
			local.Args = ins.Args[f.source:]
			if f.memory != f.destination {
				return x86ResultPackedConversionInputs(local, f.conversion, state, owned, arch, nativeRead), true
			}
			if !x86ResultCheckKMask(ins, f.mask, state) {
				return false, true
			}
			index, _ := amd64VectorRegisterIndex(ins.Args[f.source].Reg, f.sourceBytes)
			input := x86CallerVectorByteMask(int64(f.inputBytes))
			if state.vectorBytes(index)&input != input {
				return false, true
			}
			destination := ins.Args[f.destination]
			return nativeRead && x86OrdinaryNativeMemoryOperand(destination, arch) &&
				x86ResultIncomingPointerAddressIdentity(destination, state, arch), true
		}
		// Four-source AVX-512 FMA (V4FMADDPS/SS, V4FNMADDPS/SS).
		if form, known, err := x86FourSourceProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) || form.memory.Kind == OpFP {
				return false, true
			}
			required := x86CallerVectorByteMask(form.inputBytes())
			for position := 0; position < 4; position++ {
				if state.vectorBytes(form.sourceBase+position)&required != required {
					return false, true
				}
			}
			operandBuf[0] = x86TypedByteOperand{operand: form.memory, width: 16, read: true}
			operandBuf[1] = x86TypedByteOperand{
				operand: form.destination, width: int64(form.byteWidth()),
				read: true, write: true, requiredBytes: required,
			}
			if form.spec.scalar {
				operandBuf[1].preservedBytes = 0xffff &^ required
			}
			n := 2
			if form.maskIndex >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.maskIndex], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(false)}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// Floating-point helpers (VGETEXP/VGETMANT/VRNDSCALE/VREDUCE/VSCALEF/VFIXUPIMM/VRCP14/VRSQRT14/VRCP28/VRSQRT28/VFPCLASS).
		if form, known, err := x86FloatingHelperProperties(ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			if form.memory >= 0 && !form.spec.scalar && ins.Args[form.first].Kind == OpFP {
				return false, true
			}
			required := x86CallerVectorByteMask(int64(form.activeBytes()))
			firstWidth := int64(form.byteWidth)
			if form.memory >= 0 {
				firstWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[form.first], width: firstWidth, read: true, requiredBytes: required}
			n := 1
			var preservedFrom int8
			if form.second >= 0 {
				operandBuf[n] = x86TypedByteOperand{
					operand: ins.Args[form.second], width: int64(form.byteWidth),
					read: form.spec.second, requiredBytes: required,
				}
				n++
				if form.spec.scalar {
					preservedFrom = int8(n)
				}
			}
			destOp := x86TypedByteOperand{operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true}
			if form.spec.maskResult {
				destOp.width = 8
			} else {
				destOp.read = form.spec.readDestination || form.mask >= 0 && !form.properties.zeroing
				destOp.requiredBytes = required
				if form.spec.scalar {
					destOp.preservedBytes = 0xffff &^ required
				}
			}
			operandBuf[n] = destOp
			n++
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{
				operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(false),
				preservedFromOperand: preservedFrom,
			}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// Mask blend (VPBLENDM*, VBLENDM*).
		if form, known, err := x86MaskBlendProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			firstWidth := int64(form.byteWidth)
			if form.memory >= 0 {
				firstWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[form.first], width: firstWidth, read: true}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true}
			n := 2
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
				if !form.zeroing {
					operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.second], width: int64(form.byteWidth), read: true}
					n++
				}
			}
			effect := x86TypedByteEffect{operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(false)}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// Packed VNNI dot products (VPDP*).
		if form, known, err := x86PackedDotProperties(ins.Op, ins, arch); known {
			if err != nil || x86Mode32VectorRegisterContext(ins, arch) != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawPackedDotSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			} else if ins.x86PackedDotEncoding != x86RawPackedDotAbsent {
				return false, true // A named source cannot invent a decoder generation.
			}
			effect, n := x86TypedFixedVectorInputsInto(&operandBuf, ins, form.x86PackedBinaryForm, true)
			if form.broadcast && form.memory < 0 {
				operandBuf[0].requiredBytes = 15
			}
			effect.operands = operandBuf[:n]
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// Qword bit lookup / multishift (VPMULTISHIFTQB, VPSHUFBITQMB).
		if form, known, err := x86QwordLookupProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawOrdinaryVectorSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			firstWidth := int64(form.byteWidth)
			if form.memory >= 0 {
				firstWidth = int64(form.memoryBytes)
			}
			operandBuf[0] = x86TypedByteOperand{operand: ins.Args[form.first], width: firstWidth, read: true}
			operandBuf[1] = x86TypedByteOperand{operand: ins.Args[form.second], width: int64(form.byteWidth), read: true}
			destOp := x86TypedByteOperand{operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true}
			if form.spec.output == amd64QwordBitLookupMask {
				destOp.width = 8
			} else {
				destOp.read = form.mask >= 0 && !form.zeroing
			}
			operandBuf[2] = destOp
			n := 3
			if form.mask >= 0 {
				operandBuf[n] = x86TypedByteOperand{operand: ins.Args[form.mask], width: 8, read: true}
				n++
			}
			effect := x86TypedByteEffect{operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(false)}
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}
		// 128-bit lane permute (VPERM2F128, VPERM2I128).
		if form, known, err := x86Permute128Properties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawPermute128Source(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			} else if ins.x86Permute128VEX {
				return false, true
			}
			first, ok := x86ResultReadVectorSourceMask(ins, ins.Args[form.first], form.memory >= 0,
				32, 32, 32, state, owned, arch, nativeRead)
			if !ok {
				return false, true
			}
			second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, 32)
			if !form.inputsDefined(first, state.vectorBytes(second)) {
				return false, true
			}
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, 32)
			state.writeVector(destination, 32, 0xffffffff, false)
			return true, true
		}
		// Element permute (VPERMIL*, VPERMP*, VPERMD/Q/W/B).
		if f, known, err := x86ElementPermuteProperties(ins.Op, ins, arch); known {
			if err != nil || !x86ResultNamedPredicateInstruction(ins) {
				return false, true
			}
			if !x86ResultCheckKMask(ins, f.mask, state) {
				return false, true
			}
			source, ok := x86ResultReadVectorSourceMask(ins, ins.Args[f.source], f.memory >= 0,
				f.byteWidth, f.memoryBytes, f.memoryBytes, state, owned, arch, nativeRead)
			if !ok {
				return false, true
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
					return false, true
				}
				bytes := f.bits / 8
				for lane := 0; lane < f.byteWidth/bytes; lane++ {
					controlByte := lane * bytes
					if f.broadcast && !f.wholeVector {
						controlByte = 0
					}
					if control>>uint(controlByte)&1 == 0 {
						return false, true
					}
				}
				defined = x86CallerVectorByteMask(int64(f.byteWidth))
			}
			destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
			if f.mask >= 0 && !f.zeroing {
				defined &= state.vectorBytes(destination)
			}
			state.writeVector(destination, f.byteWidth, defined, false)
			return true, true
		}
		// Lowering-only raw FP16 conversion and binary families.
		if nativeRead {
			if _, known, _ := x86FP16ConversionProperties(ins, arch); known {
				f, valid := x86RawFP16ConversionSourceForm(ins, arch)
				if !valid {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
				srcWidth := int64(f.sourceBytes)
				if ins.Args[0].Kind != OpReg {
					srcWidth = int64(f.memoryBytes)
				}
				outputMask := x86CallerVectorByteMask(int64(f.outputBytes))
				operandBuf[0] = x86TypedByteOperand{
					operand: ins.Args[0], width: srcWidth, read: true,
					requiredBytes: x86CallerVectorByteMask(int64(f.inputBytes)),
				}
				destOp := x86TypedByteOperand{
					operand: ins.Args[f.destination], width: int64(f.byteWidth),
					read: f.mask >= 0 && !f.controls.zeroing, write: true, requiredBytes: outputMask,
				}
				n := 1
				var preservedFrom int8
				if f.upper >= 0 {
					destOp.preservedBytes = 0xffff &^ outputMask
					operandBuf[n] = x86TypedByteOperand{operand: ins.Args[f.upper], width: 16}
					n++
					preservedFrom = int8(n)
				}
				operandBuf[n] = destOp
				n++
				if f.mask >= 0 {
					operandBuf[n] = x86TypedByteOperand{operand: ins.Args[f.mask], width: 8, read: true}
					n++
				}
				effect := x86TypedByteEffect{
					operands: operandBuf[:n], vector: x86ResultVectorUpperWrite(false),
					preservedFromOperand: preservedFrom,
				}
				return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, true), true
			}
			if f, known, err := x86FP16BinaryProperties(ins, arch); known {
				if err != nil {
					return false, true
				}
				return x86ScalarFPFloatBinaryTransferWithRead(ins, f.x86FloatBinaryForm, state, owned, arch, true), true
			}
		}
	}

	// Pilot 1B core typed vector families (IFMA, FMA3 incl. raw FP16, TernaryLogic,
	// IntegerMinMax, PackedArithmetic, PackedPhysical, and FixedVectorValue).
	if op0 == 'P' || op0 == 'V' || op0 == 'G' {
		// 1. IFMA (named and exact decoded raw).
		if form, known, err := x86IFMAProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) {
				if !nativeRead || !x86RawOrdinaryVectorSource(ins, arch) {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			}
			effect, n := x86TypedIFMAEffectForFormInto(&operandBuf, ins, form)
			effect.operands = operandBuf[:n]
			return x86ResultApplyTypedVectorEffect(ins, effect, state, owned, arch, nativeRead), true
		}

		// 2. FMA3 (named, exact decoded raw, RIP literal, and lowering-only raw FP16).
		if form, known, err := amd64FMA3Properties(ins, arch); known {
			if form.spec.rawOnly {
				if !nativeRead {
					return false, false
				}
				if _, valid := x86RawFP16FMASourceForm(ins, arch); !valid {
					return false, true
				}
				ins.x86Encoded, ins.x86SourceRaw = false, nil
			} else {
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

func x86ResultPackedExtendTransfer(ins Instr, form x86PackedExtendForm, state *x86ResultState,
	owned []bool, arch string, conditionalNativeRead bool) bool {
	if !x86ResultCheckKMask(ins, form.mask, state) {
		return false
	}
	var input uint64
	if form.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[0], int64(form.memoryBytes), state, owned, arch, conditionalNativeRead) {
			return false
		}
		input = x86CallerVectorByteMask(int64(form.memoryBytes))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[0].Reg, form.sourceRegisterBytes)
		input = state.vectorBytes(index)
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	initialized := x86PackedExtendDefinedBytes(form, input, state.vectorBytes(destination))
	state.writeVector(destination, form.byteWidth, initialized, !form.spec.vector)
	return true
}

func x86ResultNamedCompareLaneTransfer(ins Instr, form x86PackedIntegerCompareForm,
	state *x86ResultState, owned []bool, arch string) (bool, bool) {
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	defined := required
	if !form.identicalVectorInputs(ins) {
		for _, input := range []int{form.first, form.second} {
			operand := ins.Args[input]
			if input == form.first {
				operand = form.source
			}
			if input == form.memory {
				if !x86ResultReadWithNativeContinuation(ins, operand, int64(form.memoryBytes), state, owned, arch, true) {
					return false, true
				}
				continue
			}
			index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
			if !valid {
				return false, true
			}
			defined &= state.vectorBytes(index)
		}
	}
	laneBytes := form.spec.laneBits / 8
	for offset := 0; offset < form.byteWidth; offset += laneBytes {
		lane := x86CallerVectorByteMask(int64(laneBytes)) << uint(offset)
		if defined&lane != lane {
			defined &^= lane
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth, defined, form.legacy)
	return true, true
}

func x86ResultVectorCompareTransfer(ins Instr, form x86PackedIntegerCompareForm, state *x86ResultState,
	owned []bool, arch string, nativeRead bool) (bool, bool) {
	if !x86ResultCheckKMask(ins, form.mask, state) {
		return false, true
	}
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	for _, input := range []int{form.first, form.second} {
		if form.identicalVectorInputs(ins) {
			break
		}
		operand := ins.Args[input]
		if input == form.first {
			operand = form.source
		}
		if input == form.memory {
			if !x86ResultReadWithNativeContinuation(ins, operand, int64(form.memoryBytes), state, owned, arch, nativeRead) {
				return false, true
			}
			continue
		}
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		if !valid || state.vectorBytes(index)&required != required {
			return false, true
		}
	}
	destination := ins.Args[form.destination].Reg
	if form.maskResult {
		index, _ := amd64ParseKReg(destination)
		state.masks[index] = true
	} else {
		index, _ := amd64VectorRegisterIndex(destination, form.byteWidth)
		state.writeVector(index, form.byteWidth, required, form.legacy)
	}
	return true, true
}

func x86ResultPackedShiftInputs(ins Instr, form x86PackedShiftForm, state *x86ResultState, owned []bool, arch string, nativeRead bool) bool {
	if !x86ResultCheckKMask(ins, form.mask, state) {
		return false
	}
	if form.memory >= 0 {
		memory := ins.Args[form.memory]
		if _, static := x86StaticSBReadAddress(memory, arch); form.legacy && !static &&
			(!nativeRead || !x86OrdinaryNativeMemoryOperand(memory, arch)) {
			return false
		}
		if !x86ResultReadWithNativeContinuation(ins, memory, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false
		}
	}
	bytes := func(index int) uint64 {
		if index == form.memory {
			return x86CallerVectorByteMask(int64(form.byteWidth))
		}
		operand := ins.Args[index]
		register, _ := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
		return state.vectorBytes(register)
	}
	data, counts := bytes(form.data), ^uint64(0)
	if form.countOperand.Kind != OpImm {
		counts = bytes(form.count)
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth,
		x86PackedShiftDefinedBytes(form, data, counts, state.vectorBytes(destination)), form.legacy)
	return true
}
