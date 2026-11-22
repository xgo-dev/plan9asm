package plan9asm

import "golang.org/x/arch/x86/x86asm"

type x86NumericalNativeBoundary struct {
	PC     int64
	Length int
}

// This is a byte-boundary observation, not a raw/source/literal or memory
// capability. In particular, VEX/EVEX instructions and the separate legacy
// ADX physical projection are never put into scalar:
// numerical-read binding still needs a real x86asm scalar decode, its exact
// original source ordinal, relocation, layout, owner and live source guard.
// Failure discards the complete observation, including otherwise valid prefixes
// of the TEXT. Unreachable bytes after RET or a branch are still checked.
func x86NumericalNativeBoundaries(code []byte, mode int) ([]x86NumericalNativeBoundary, map[int64]x86asm.Inst, error) {
	if mode != 32 && mode != 64 || len(code) == 0 {
		return nil, nil, numericalSBContext("empty TEXT or unknown native x86 mode")
	}
	var boundaries []x86NumericalNativeBoundary
	scalar := make(map[int64]x86asm.Inst)
	for pc := int64(0); pc < int64(len(code)); {
		remaining := code[pc:]
		length := 0
		if x86NumericalVectorPrefix(remaining, mode) {
			var err error
			length, err = x86NumericalVectorBoundary(remaining, mode)
			if err != nil {
				return nil, nil, numericalSBContext("whole native vector boundary at %d: %v", pc, err)
			}
		} else if _, shaLength, known, err := decodedX86SHAInstructionWithMemory(remaining, mode, x86RawMemoryDecoder{physicalPC: true}); known || err != nil {
			if err != nil {
				return nil, nil, numericalSBContext("whole native SHA boundary at %d: %v", pc, err)
			}
			length = shaLength
		} else if _, adxLength, _, known, err := decodeX86RawADXWithMemory(remaining, 0, mode, x86RawMemoryDecoder{physicalPC: true}); known || err != nil {
			if err != nil {
				return nil, nil, numericalSBContext("whole native ADX boundary at %d: %v", pc, err)
			}
			length = adxLength
		} else {
			native, err := x86asm.Decode(remaining, mode)
			if err != nil || native.Op == 0 || native.Op == x86asm.CALL || native.Op == x86asm.LCALL {
				return nil, nil, numericalSBContext("unknown/calling whole native instruction boundary at %d", pc)
			}
			for _, prefix := range native.Prefix {
				if prefix.IsVEX() || prefix&x86asm.PrefixInvalid != 0 {
					return nil, nil, numericalSBContext("unbound vector or invalid native prefix at %d", pc)
				}
			}
			length = native.Len
			scalar[pc] = native
		}
		if length <= 0 || length > 15 || length > len(remaining) {
			return nil, nil, numericalSBContext("invalid complete native instruction length at %d", pc)
		}
		boundaries = append(boundaries, x86NumericalNativeBoundary{PC: pc, Length: length})
		pc += int64(length)
	}
	return boundaries, scalar, nil
}

// Detect even incomplete/unsupported vector prefixes before generic decoding:
// x/arch can report an unrelated legacy instruction and a wrong positive Len.
// In mode32, C4/C5/62 with a memory ModRM remain legacy LES/LDS/BOUND.
func x86NumericalVectorPrefix(code []byte, mode int) bool {
	for i, value := range code {
		switch {
		case value == 0xc4 || value == 0xc5 || value == 0x62:
			return mode == 64 || i+1 == len(code) || code[i+1]&0xc0 == 0xc0
		case value == 0x26 || value == 0x2e || value == 0x36 || value == 0x3e ||
			value == 0x64 || value == 0x65 || value == 0x66 || value == 0x67 ||
			value == 0xf0 || value == 0xf2 || value == 0xf3 || mode == 64 && value&0xf0 == 0x40:
			if i == 14 {
				return false
			}
		default:
			return false
		}
	}
	return false
}

func x86NumericalVectorBoundary(code []byte, mode int) (int, error) {
	if ins, length, known, err := decodedX86RawVSIBInstruction(code, mode); known {
		if err == nil && mode == 32 {
			err = x86Mode32VectorRegisterContext(ins, "386")
		}
		return length, err
	}
	memory := x86RawMemoryDecoder{physicalPC: true}
	if length, known, err := x86FourSourceNativeBoundary(code, mode, memory); known {
		return length, err
	}
	decoders := [...]func([]byte, int, x86RawMemoryDecoder) (Instr, int, bool, error){
		decodedX86ANDNInstructionWithMemory,
		decodedX86BEXTRInstructionWithMemory,
		decodedX86BLSInstructionWithMemory,
		decodedX86RawBZHIInstructionWithMemory,
		decodedX86MULXInstructionWithMemory,
		decodedX86ParallelBitsInstructionWithMemory,
		decodedX86RORXInstructionWithMemory,
		decodedX86BMI2ShiftInstructionWithMemory,
		decodedX86NumericalConversionBoundary,
		decodedX86ScalarFloatToIntegerInstructionWithMemory,
		decodedX86ScalarFlagCompareInstructionWithMemory,
		decodedX86VEXFMA3InstructionWithMemory,
		decodedX86VEXBinaryFloatInstructionWithMemory,
		decodedX86NumericalFloatingHelperBoundary,
		decodedX86VEXMXCSRInstructionWithMemory,
		decodedX86AESInstructionWithMemory,
		decodedX86GFNIInstructionWithMemory,
		decodedX86RawPackedSADInstructionWithMemory,
		decodedX86MaskMoveInstructionWithMemory,
		decodedX86PackedMoveInstructionWithMemory,
		decodedX86EVEXPackedIntegerMoveInstructionWithMemory,
		decodedX86NumericalLaneMoveBoundary,
		decodedX86VEXNonTemporalMoveInstructionWithMemory,
		decodedX86VEXPackedFloatLogicalInstructionWithMemory,
		decodedX86VEXPackedIntegerLogicalInstructionWithMemory,
		decodedX86EVEXPackedLogicalInstructionWithMemory,
		decodedX86RawEVEXFloatLogicalInstructionWithMemory,
		decodedX86VINSERT128InstructionWithMemory,
		decodedX86EVEXPackedInsertInstructionWithMemory,
		decodedX86VEXTRACT128InstructionWithMemory,
		decodedX86Permute128InstructionWithMemory,
		decodedX86NumericalBroadcastBoundary,
		decodedX86PackedIntegerCompareInstructionWithMemory,
		decodedX86PackedIntegerArithmeticInstructionWithMemory,
		decodedX86PackedAverageInstructionWithMemory,
		decodedX86PackedIntegerMinMaxInstructionWithMemory,
		decodedX86PackedMultiplyInstructionWithMemory,
		decodedX86DwordToQwordMultiplyInstructionWithMemory,
		decodedX86VEXPackedMADDInstructionWithMemory,
		decodedX86EVEXPackedMADDInstructionWithMemory,
		decodedX86PackedUniformShiftInstructionWithMemory,
		decodedX86PerLaneVariableShiftInstructionWithMemory,
		decodedX86RawVectorByteShiftInstructionWithMemory,
		decodedX86VPSHUFBInstructionWithMemory,
		decodedX86PackedShuffleInstructionWithMemory,
		decodedX86PackedAlignRightInstructionWithMemory,
		decodedX86ImmediatePackedBlendInstructionWithMemory,
		decodedX86VPINSRInstructionWithMemory,
		decodedX86EVEXVPINSRInstructionWithMemory,
		decodedX86PackedScalarExtractInstructionWithMemory,
		decodedX86PackedCompactInstruction,
		decodedX86VMOVQInstructionWithMemory,
		decodedX86VEXVectorTestInstructionWithMemory,
		decodedX86InLaneFloatingPermuteInstructionWithMemory,
		decodedX86RawQwordPermuteInstructionWithMemory,
		decodedX86VariableDwordPermuteInstructionWithMemory,
		decodedX86EVEXVariableDwordPermuteInstructionWithMemory,
		decodedX86PackedImmediateRotateInstructionWithMemory,
		decodedX86RawVariableRotateInstructionWithMemory,
		decodedX86Shuffle128BitBlocksInstructionWithMemory,
		decodedX86RawMaskBlendInstructionWithMemory,
		decodedX86FloatingUnpackInstructionWithMemory,
		decodedX86EVEXPackedUnpackInstructionWithMemory,
		decodedX86VEXPackedUnpackBoundary,
		decodedX86PackedExtendInstructionWithMemory,
		decodedX86SingleSourceNarrowInstructionWithMemory,
		decodedX86VectorPackedSaturatingNarrowInstructionWithMemory,
		decodedX86VectorAlignInstructionWithMemory,
		decodedX86FunnelShiftInstructionWithMemory,
		decodedX86RawVectorBitCountInstructionWithMemory,
		decodedX86NumericalConflictBoundary,
		decodedX86IndexedPermuteInstructionWithMemory,
		decodedX86NumericalSingleTablePermuteBoundary,
		decodedX86NumericalQwordBinaryBoundary,
		decodedX86RawMaskCompareInstructionWithMemory,
		decodedX86RawPackedTestMaskInstructionWithMemory,
		decodedX86VectorFloatCompareInstructionWithMemory,
		decodedX86RawPackedAbsInstructionWithMemory,
		decodedX86RawPackedSignInstructionWithMemory,
		decodedX86VSHUFPSInstructionWithMemory,
		decodedX86IntegerPackedDotInstructionWithMemory,
	}
	if ins, length, known, err := decodedX86VEXMoveMaskInstruction(code, mode); known || err != nil {
		if err == nil && mode == 32 {
			err = x86Mode32VectorRegisterContext(ins, "386")
		}
		return length, err
	}
	for _, decode := range decoders {
		if ins, length, known, err := decode(code, mode, memory); known || err != nil {
			if err == nil && mode == 32 {
				err = x86Mode32VectorRegisterContext(ins, "386")
			}
			return length, err
		}
	}
	if p, known := decodeX86RawVectorEncoding(code); known && p.mapNumber == 3 && p.pp == 1 && p.opcode == 0x44 {
		_, length, _, err := decodedX86RawVectorCLMULInstructionWithMemory(code, mode, p, memory)
		return length, err
	}
	// The complete physical EVEX grammar is shared with the source decoder.
	// Its separate source-syntax validation deliberately cannot interpret RIP.
	if _, length, known, err := decodedX86TernaryLogicInstructionWithMemory(code, mode, memory); known || err != nil {
		return length, err
	}
	if _, length, known, err := decodedX86VectorZeroInstruction(code, mode); known || err != nil {
		return length, err
	}
	return 0, numericalSBContext("unregistered or truncated whole native VEX/EVEX encoding")
}

func decodedX86NumericalLaneMoveBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, known := decodeX86RawVectorEncoding(code)
	if !known || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	switch p.opcode {
	case 0x12, 0x16:
		if p.pp >= 2 {
			return decodedX86DuplicateMoveInstructionWithMemory(code, mode, memory)
		}
		if ins, size, known, err := decodedX86RawVectorHighLowMoveInstruction(code, mode); known || err != nil {
			return ins, size, known, err
		}
	case 0x13, 0x17:
	default:
		return Instr{}, 0, false, nil
	}
	return decodedX86RawVectorHalfMemoryInstructionWithMemory(code, mode, memory)
}

// VPERMB/W uses the same two-source physical shape as the indexed family.
// This recognises named-Go bytes without adding a raw-source consumer.
func decodedX86NumericalSingleTablePermuteBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, known := decodeX86RawVectorEncoding(code)
	if !known || !p.evex || p.mapNumber != 2 || p.pp != 1 || p.opcode != 0x8d {
		return Instr{}, 0, false, nil
	}
	op := Op("VPERMB")
	if p.w {
		op = "VPERMW"
	}
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, op, 0, memory)
}

func decodedX86NumericalQwordBinaryBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, known := decodeX86RawVectorEncoding(code)
	if !known || !p.evex || p.mapNumber != 2 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	switch p.opcode {
	case 0x83, 0x8f:
		return decodedX86EVEXQwordBinaryInstruction(code, mode, true, memory)
	case 0xb4, 0xb5:
		return decodedX86EVEXQwordBinaryInstruction(code, mode, false, memory)
	default:
		return Instr{}, 0, false, nil
	}
}

func decodedX86NumericalConflictBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 || p.opcode != 0xc4 {
		return Instr{}, 0, false, nil
	}
	op, laneBytes := Op("VPCONFLICTD"), 4
	if p.w {
		op, laneBytes = "VPCONFLICTQ", 8
	}
	return decodedX86EVEXUnaryVectorWithMemory(code, mode, p, op, laneBytes, memory)
}

func decodedX86VEXPackedUnpackBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, known := decodeX86RawVectorEncoding(code)
	if !known || p.evex || p.mapNumber != 1 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	form, known := x86RawEVEXUnpackForms[p.opcode]
	if !known {
		return Instr{}, 0, false, nil
	}
	// VEX always reads the full vector tuple. The EVEX lane width only
	// affects broadcast scaling, which cannot occur in this encoding.
	return decodedX86BinaryVectorOperandsWithMemory(code, p, mode, form.op, 0, memory)
}

// Keep the original raw-source dispatch order: EVEX 19/W0 is F32X2, not
// scalar SD/W1, and 59/W0 is I32X2, not integer Q/W1. The specialized source
// decoders retain their own reserved-encoding contracts and memory policy.
func decodedX86NumericalBroadcastBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	if ins, length, known, err := decodedX86RawBlockBroadcastInstructionWithMemory(code, mode, memory); known || err != nil {
		return ins, length, known, err
	}
	if ins, length, known, err := decodedX86ScalarBroadcastInstructionWithMemory(code, mode, memory); known || err != nil {
		return ins, length, known, err
	}
	return decodedX86VEXPackedBroadcastInstructionWithMemory(code, mode, memory)
}

func decodedX86NumericalConversionBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	if ins, length, known, err := decodedX86PackedNumericConversionInstructionWithMemory(code, mode, memory); known || err != nil {
		return ins, length, known, err
	}
	p, known := decodeX86RawVectorEncoding(code)
	if !known {
		return Instr{}, 0, false, nil
	}
	switch {
	case p.mapNumber == 2 && p.opcode == 0x13, p.mapNumber == 3 && p.opcode == 0x1d:
		return decodedX86PackedHalfConversionInstructionWithMemory(code, mode, memory)
	case p.mapNumber != 1:
		return Instr{}, 0, false, nil
	case p.opcode == 0x5a && p.pp < 2:
		return decodedX86PackedPrecisionConvertInstructionWithMemory(code, mode, memory)
	case p.opcode == 0x5a:
		return decodedX86ScalarPrecisionConvertInstructionWithMemory(code, mode, memory)
	case p.opcode == 0x51 && p.pp < 2, p.opcode == 0x5b && p.pp == 0:
		return decodedX86SameWidthConversionInstructionWithMemory(code, mode, memory)
	case p.opcode == 0xe6 && p.pp == 2:
		return decodedX86PackedDoubleDwordInstructionWithMemory(code, mode, memory)
	}
	return Instr{}, 0, false, nil
}
