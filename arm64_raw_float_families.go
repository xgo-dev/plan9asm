package plan9asm

// Preserve the previous lowering precedence. Lowering, continuation provenance
// and raw-pool GP effects all consume this same typed family registration.
var arm64RawFloatFamilies = [...]arm64RawFamily{
	arm64RawNoGPOrMemoryForm(decodeARM64RawBFloatDot, (*arm64Ctx).lowerRawBFloatDot),
	arm64RawNoGPOrMemoryForm(decodeARM64RawBFloatMatrix, (*arm64Ctx).lowerRawBFloatMatrix),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFloatMultiplyLong, (*arm64Ctx).lowerRawFloatMultiplyLong),
	arm64RawNoGPOrMemoryForm(decodeARM64RawCVTF, (*arm64Ctx).lowerRawCVTF),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFMLA, (*arm64Ctx).lowerRawFMLA),
	arm64RawNoGPOrMemoryForm(decodeARM64RawHalfFMA, (*arm64Ctx).lowerRawHalfFMA),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFMULByElement, (*arm64Ctx).lowerRawFMULByElement),
	arm64RawNoGPOrMemoryForm(decodeARM64RawScalarHalfUnary, (*arm64Ctx).lowerRawScalarHalfUnary),
	arm64RawNoGPOrMemoryForm(decodeARM64RawScalarVectorFCVTZ, (*arm64Ctx).lowerRawScalarVectorFCVTZ),
	arm64RawNoGPOrMemoryForm(decodeARM64RawScalarFloatBinary, (*arm64Ctx).lowerRawScalarFloatBinary),
	arm64RawNoGPOrMemoryForm(decodeARM64RawScalarFloatCompare, (*arm64Ctx).lowerRawScalarFloatCompare),
	arm64RawNoGPOrMemoryForm(decodeARM64RawConditionalCompare, (*arm64Ctx).lowerARM64ConditionalCompare),
	arm64RawNoGPOrMemoryForm(decodeARM64RawScalarFloatSelect, (*arm64Ctx).lowerRawScalarFloatSelect),
	arm64RawNoGPOrMemoryForm(decodeARM64RawScalarFloatImmediate, (*arm64Ctx).lowerRawScalarFloatImmediate),
	arm64RawForm(decodeARM64RawScalarIntToFloat, (*arm64Ctx).lowerRawScalarIntToFloat,
		func(form arm64RawScalarIntToFloat) arm64RawContinuationEffects {
			if form.simdInteger {
				return arm64RawContinuationEffects{}
			}
			return arm64RawContinuationEffects{gpReads: arm64RawGPBit(form.source)}
		}),
	arm64RawForm(decodeARM64RawFixedIntToFloat, (*arm64Ctx).lowerRawFixedIntToFloat,
		func(form arm64RawFixedIntToFloat) arm64RawContinuationEffects {
			if form.vectorSource {
				return arm64RawContinuationEffects{}
			}
			return arm64RawContinuationEffects{gpReads: arm64RawGPBit(form.source)}
		}),
	arm64RawForm(decodeARM64RawFloatGPMove, (*arm64Ctx).lowerRawFloatGPMove,
		func(form arm64RawFloatGPMove) arm64RawContinuationEffects {
			if form.toFloat {
				return arm64RawContinuationEffects{gpReads: arm64RawGPBit(form.gpReg)}
			}
			return arm64RawContinuationEffects{gpWrites: arm64RawGPBit(form.gpReg)}
		}),
	arm64RawNoGPOrMemoryForm(decodeARM64RawBFloatConvert, (*arm64Ctx).lowerRawBFloatConvert),
	arm64RawNoGPOrMemoryForm(decodeARM64RawVectorFloatRound, (*arm64Ctx).lowerRawVectorFloatRound),
	arm64RawNoGPOrMemoryForm(decodeARM64RawVectorFloatNarrow, (*arm64Ctx).lowerRawVectorFloatNarrow),
	arm64RawNoGPOrMemoryForm(decodeARM64RawVectorFloatWiden, (*arm64Ctx).lowerRawVectorFloatWiden),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFloatMinMaxAcross, (*arm64Ctx).lowerRawFloatMinMaxAcross),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFADDP, (*arm64Ctx).lowerRawFADDP),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFloatPairwiseMinMax, (*arm64Ctx).lowerRawFloatPairwiseMinMax),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFloatBinary, (*arm64Ctx).lowerRawFloatBinary),
	arm64RawNoGPOrMemoryForm(decodeARM64RawReciprocalEstimate, (*arm64Ctx).lowerRawReciprocalEstimate),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFSQRT, (*arm64Ctx).lowerRawFSQRT),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFloatAbsNeg, (*arm64Ctx).lowerRawFloatAbsNeg),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFloatCompare, (*arm64Ctx).lowerRawFloatCompare),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFloatImmediate, (*arm64Ctx).lowerRawFloatImmediate),
	arm64RawForm(decodeARM64RawScalarFCVTToInt, (*arm64Ctx).lowerRawScalarFCVTToInt,
		func(form arm64RawScalarFCVTToInt) arm64RawContinuationEffects {
			return arm64RawContinuationEffects{gpWrites: arm64RawGPBit(form.destination)}
		}),
	arm64RawNoGPOrMemoryForm(decodeARM64RawFCVTZ, (*arm64Ctx).lowerRawFCVTZ),
}

func decodeARM64RawFloatFamily(word uint32) (arm64RawFamily, arm64RawContinuationEffects, bool) {
	for _, family := range arm64RawFloatFamilies {
		if effects, ok := family.effects(word); ok {
			return family, effects, true
		}
	}
	return arm64RawFamily{}, arm64RawContinuationEffects{}, false
}
