package plan9asm

import "reflect"

// x86ResultApplyTypedGPEffect evaluates a validated scalar GP x86TypedByteEffect
// against x86ResultState. All ordered inputs are validated before any output
// write so rejected transfers leave state untouched.
func x86ResultApplyTypedGPEffect(ins Instr, effect x86TypedByteEffect,
	state *x86ResultState, owned []bool, resultOffset int64, arch string,
	nativeRead, segmentRead, rejectPointerGP bool) bool {
	if effect.dynamicMemory || state.flags&effect.flagsRead != effect.flagsRead {
		return false
	}
	for _, operand := range effect.operands {
		if !operand.read {
			continue
		}
		if rejectPointerGP && operand.operand.Kind == OpReg {
			index, _, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
			if !valid || state.pointerGP[index] {
				return false
			}
		}
		if !x86ResultReadWithNativeAddress(ins, operand.operand, operand.width, state, owned, arch, nativeRead, segmentRead) {
			return false
		}
	}
	for _, operand := range effect.operands {
		if operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, resultOffset, arch) {
			return false
		}
	}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true
}

func x86ResultScalarBitFieldStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64,
	arch string, nativeRead bool) (bool, bool) {
	effect, known, err := x86TypedScalarBitFieldByteEffect(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	return x86ResultApplyTypedGPEffect(ins, effect, state, owned, resultOffset, arch, nativeRead, false, true), true
}

// x86LoweredTypedGPEffectStep consolidates paired lowering native-read and raw
// provenance projection for scalar GP instruction families onto the shared
// x86TypedByteEffect interpreter. Standalone observers never call this step.
func x86LoweredTypedGPEffectStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	if len(ins.Op) == 0 || ins.x86NumericalRead != nil {
		return false, false
	}
	op0 := ins.Op[0]
	if op0 >= 'a' && op0 <= 'z' {
		op0 -= 'a' - 'A'
	}
	switch op0 {
	case 'A', 'B', 'C', 'I', 'L', 'M', 'P', 'R', 'S', 'T', 'V':
	default:
		return false, false
	}

	switch op0 {
	case 'A':
		// ADX (ADCX, ADOX) - named native read + exact raw.
		if form, known, err := x86ADXProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			local := ins
			if !x86ResultNamedPredicateInstruction(ins) {
				if !x86RawADXSource(ins, arch) {
					return false, true
				}
				local.x86Encoded, local.x86SourceRaw, local.x86AddressBits = false, nil, 0
			}
			if !x86OrdinaryNativeMemoryOperand(form.source, arch) {
				return x86ResultTransfer(local, state, owned, resultOffset, arch), true
			}
			effect, _, err := x86TypedADXByteEffect(local.Op, local, arch)
			if err != nil {
				return false, true
			}
			return x86ResultApplyTypedGPEffect(local, effect, state, owned, resultOffset, arch, true, false, false), true
		}
		// Ternary GP (ANDN) - named native read + exact raw.
		if form, known, err := x86TernaryGPProperties(ins.Op, ins, arch); known {
			return x86LoweredTernaryGPFormStep(ins, form, err, state, owned, resultOffset, arch)
		}
	case 'B':
		// Scalar bit-field (BEXTR, BZHI).
		if accepted, known := x86ResultScalarBitFieldStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted, true
		}
		// BLS (BLSI, BLSMSK, BLSR) native memory read.
		if form, known, err := x86BLSProperties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if form.source.Kind != OpMem || form.source.Mem.Sym != "" {
				return false, false
			}
			effect, _, _ := x86TypedBLSByteEffect(ins.Op, ins, arch)
			return x86ResultApplyTypedGPEffect(ins, effect, state, owned, resultOffset, arch, true, false, false), true
		}
	case 'C':
		// CRC32 native memory read.
		if form, known, err := x86CRC32Properties(ins.Op, ins, arch); known {
			if err != nil {
				return false, true
			}
			if !x86ResultNamedPredicateInstruction(ins) ||
				!x86ResultRead(form.destination, 4, state, owned, arch) ||
				!x86ResultReadWithNativeContinuation(ins, form.source, int64(form.bits/8), state, owned, arch, true) {
				return false, true
			}
			return x86ResultStore(form.destination, 4, state, owned, resultOffset, arch), true
		}
		// Raw accumulator sign-extend (CBW/CWDE/CDQE/CWD/CDQ/CQO).
		if !x86ResultNamedPredicateInstruction(ins) {
			if _, known, _ := x86AccumulatorSignExtendProperties(ins.Op, ins, arch); known {
				if !x86RawAccumulatorSignExtendSource(ins, arch) {
					return false, true
				}
				local := ins
				local.x86Encoded, local.x86SourceRaw = false, nil
				return x86ResultTransfer(local, state, owned, resultOffset, arch), true
			}
		}
	case 'I', 'M':
		// MULX - named native read + exact raw + nontrapping unknown fallback.
		if op0 == 'M' {
			if form, known, err := x86MULXProperties(ins.Op, ins, arch); known {
				if err != nil {
					return false, true
				}
				local := ins
				if !x86ResultNamedPredicateInstruction(ins) {
					if !x86RawMULXSource(ins, arch) {
						return false, true
					}
					local.x86Encoded, local.x86SourceRaw = false, nil
				}
				if !x86RegisterAddressedNativeMemoryOperand(form.source, arch) {
					next := state.clone()
					next.loweredStaticReads, next.goReadOnlyRead = state.loweredStaticReads, state.goReadOnlyRead
					if x86ResultTransfer(local, &next, owned, resultOffset, arch) {
						*state = next
						return true, true
					}
					if form.needsNativeProof(ins, arch) {
						return false, true
					}
					return x86MULXUnknownNumericalResults(local, state, owned, arch), true
				}
				effect, _, _ := x86TypedMULXByteEffect(local.Op, local, arch)
				return x86ResultApplyTypedGPEffect(local, effect, state, owned, resultOffset, arch, true, false, false), true
			}
			// MOVBE - named native load/store + exact raw.
			if form, known, err := x86MOVBEProperties(ins.Op, ins, arch); known {
				if err != nil {
					return false, true
				}
				local := ins
				if !x86ResultNamedPredicateInstruction(ins) {
					if !x86RawMOVBESource(ins, arch) {
						return false, true
					}
					local.x86Encoded, local.x86SourceRaw = false, nil
				}
				width := int64(form.bits / 8)
				if form.store && x86OrdinaryNativeMemoryOperand(form.destination, arch) {
					address := x86ResultIncomingPointerAddressIdentity(form.destination, state, arch) ||
						x86ResultSharedNumericalAddress(local, form.destination, state, arch, form.source)
					return address && x86ResultRead(form.source, width, state, owned, arch), true
				}
				if !form.store && x86OrdinaryNativeMemoryOperand(form.source, arch) {
					if !x86ResultReadWithNativeContinuation(local, form.source, width, state, owned, arch, true) {
						return false, true
					}
					return x86ResultStore(form.destination, width, state, owned, resultOffset, arch), true
				}
				if x86ResultNamedPredicateInstruction(ins) {
					return false, false
				}
				return x86ResultTransfer(local, state, owned, resultOffset, arch), true
			}
		}
		// One-operand implicit MUL/IMUL native memory read.
		if form, known, err := x86ImplicitMultiplyProperties(ins.Op, ins, arch); known {
			if form.source.Kind != OpMem || form.source.Mem.Sym != "" {
				return false, false
			}
			if err != nil || !x86ResultNamedPredicateInstruction(ins) ||
				form.source.Mem.Segment != "" || !x86RegisterAddressedNativeMemoryOperand(form.source, arch) {
				return false, true
			}
			effect, known, err := x86TypedImplicitMultiplyByteEffect(ins.Op, ins, arch)
			if !known || err != nil {
				return false, true
			}
			return x86ResultApplyTypedGPEffect(ins, effect, state, owned, resultOffset, arch, true, false, false), true
		}
		// Explicit 2/3-operand IMUL native memory read.
		if op0 == 'I' {
			if form, known, err := x86ExplicitIMULProperties(ins.Op, ins, arch); known {
				if err != nil || form.source.Kind != OpMem || form.source.Mem.Sym != "" ||
					!x86OrdinaryNativeMemoryOperand(form.source, arch) {
					return false, false
				}
				if !x86ResultNamedPredicateInstruction(ins) {
					return false, true
				}
				return x86ResultApplyTypedGPEffect(ins, x86ExplicitIMULByteEffect(form), state, owned, resultOffset, arch, true, true, true), true
			}
		}
	case 'P':
		// Ternary GP (PDEP, PEXT) - named native read + exact raw.
		if form, known, err := x86TernaryGPProperties(ins.Op, ins, arch); known {
			return x86LoweredTernaryGPFormStep(ins, form, err, state, owned, resultOffset, arch)
		}
	case 'R', 'S':
		// Raw BMI2 shifts/rotates (RORX, SARX, SHLX, SHRX).
		if !x86ResultNamedPredicateInstruction(ins) {
			if form, known, _ := x86ScalarShiftProperties(ins.Op, ins, arch); known && form.bmi2 {
				if !x86RawBMI2ShiftSource(ins, arch) {
					return false, true
				}
				local := ins
				local.x86Encoded, local.x86SourceRaw = false, nil
				if accepted, known := x86LoweredScalarShiftMemory(local, state, owned, resultOffset, arch); known {
					return accepted, true
				}
				next := state.clone()
				if x86ResultTransfer(local, &next, owned, resultOffset, arch) {
					*state = next
					return true, true
				}
				return x86LoweredPureGPUnknownTransfer(local, state, arch), true
			}
		}
	case 'V':
		// Raw VZEROUPPER/VZEROALL.
		if !x86ResultNamedPredicateInstruction(ins) {
			if _, known, _ := x86VectorZeroProperties(ins, arch); known {
				if !x86RawVectorZeroSource(ins, arch) {
					return false, true
				}
				local := ins
				local.x86Encoded, local.x86SourceRaw = false, nil
				return x86ResultTransfer(local, state, owned, resultOffset, arch), true
			}
		}
	}

	// Raw scalar observers (POPCNT/LZCNT/TZCNT and MOVMSK*/PMOVMSKB/VMOVMSK*)
	// plus named scalar bit-count native memory reads.
	switch op0 {
	case 'L', 'M', 'P', 'T', 'V':
		if !x86ResultNamedPredicateInstruction(ins) {
			if accepted, known := x86LoweredRawScalarObserverStep(ins, state, owned, resultOffset, arch); known {
				return accepted, true
			}
		}
		if op0 == 'L' || op0 == 'P' || op0 == 'T' {
			if effect, known, err := x86TypedScalarBitCountByteEffect(ins.Op, ins, arch); known {
				if err != nil {
					return false, true
				}
				if ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Sym != "" {
					return false, false
				}
				return x86ResultApplyTypedGPEffect(ins, effect, state, owned, resultOffset, arch, true, false, false), true
			}
		}
	}
	return false, false
}

func x86LoweredTernaryGPFormStep(ins Instr, form x86TernaryGPForm, err error,
	state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	if err != nil {
		return false, true
	}
	if x86ResultNamedPredicateInstruction(ins) && !x86OrdinaryNativeMemoryOperand(form.first, arch) {
		return false, false
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawTernaryGPSource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	if !x86OrdinaryNativeMemoryOperand(form.first, arch) {
		return x86ResultTransfer(local, state, owned, resultOffset, arch), true
	}
	effect, _, _ := x86TypedTernaryGPByteEffect(local.Op, local, arch)
	return x86ResultApplyTypedGPEffect(local, effect, state, owned, resultOffset, arch, true, false, false), true
}

func x86RawAccumulatorSignExtendSource(ins Instr, arch string) bool {
	_, known, err := x86AccumulatorSignExtendProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOperandFreeSource(ins)
}

func x86RawBMI2ShiftSource(ins Instr, arch string) bool {
	form, known, err := x86ScalarShiftProperties(ins.Op, ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && form.bmi2 && origin != nil && origin.op == ins.Op &&
		reflect.DeepEqual(origin.args, ins.Args) && origin.vectorBytes == ins.x86VectorBytes &&
		ins.x86RawNearReturn == nil && ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride &&
		ins.x86SegmentPrefix == 0 && !ins.x86RIPLiteral && ins.x86NumericalRead == nil
}

func x86RawScalarObserverSource(ins Instr, arch string) bool {
	_, count, err := x86ScalarBitCountProperties(ins.Op, ins, arch)
	if !count {
		form, mask, maskErr := x86MoveMaskProperties(ins.Op, ins, arch)
		if !mask || maskErr != nil || form.byteWidth == 8 {
			return false // Physical MMX/x87 state retains its separate owner.
		}
	}
	return err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86RawVectorZeroSource(ins Instr, arch string) bool {
	_, known, err := x86VectorZeroProperties(ins, arch)
	return known && err == nil && x86RawOperandFreeSource(ins)
}

func x86LoweredRawScalarObserverStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	_, count, _ := x86ScalarBitCountProperties(ins.Op, ins, arch)
	var maskForm x86MoveMaskForm
	if !count {
		var mask bool
		if maskForm, mask, _ = x86MoveMaskProperties(ins.Op, ins, arch); !mask {
			return false, false
		}
	}
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if !x86RawScalarObserverSource(ins, arch) {
		return false, true
	}
	if !count {
		index, _ := amd64VectorRegisterIndex(ins.Args[0].Reg, maskForm.byteWidth)
		required := x86CallerVectorByteMask(int64(maskForm.byteWidth))
		if state.vectorBytes(index)&required != required {
			return false, true
		}
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	if count && local.Args[0].Kind == OpMem && local.Args[0].Mem.Sym == "" {
		effect, known, err := x86TypedScalarBitCountByteEffect(local.Op, local, arch)
		if known && err == nil {
			return x86ResultApplyTypedGPEffect(local, effect, state, owned, resultOffset, arch, true, false, false), true
		}
	}
	return x86ResultTransfer(local, state, owned, resultOffset, arch), true
}

// Raw-only guards kept for direct raw-origin mutation unit tests.
func x86LoweredAccumulatorSignExtendResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	return x86LoweredTypedGPEffectStep(ins, state, owned, resultOffset, arch)
}

func x86LoweredBMI2ShiftResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	return x86LoweredTypedGPEffectStep(ins, state, owned, resultOffset, arch)
}

func x86LoweredVectorZeroResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	return x86LoweredTypedGPEffectStep(ins, state, owned, resultOffset, arch)
}
