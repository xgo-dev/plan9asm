package plan9asm

// These existing Advanced SIMD integer and crypto decoders accept only scalar
// FP/SIMD or vector registers. Their encoded register 30 is not GP R30, and
// register 31 is an ordinary vector register rather than XZR/SP. Retain each
// complete decoder's arrangement, lane and reserved-encoding validation.
var arm64RawVectorFamilies = [...]arm64RawFamily{
	arm64RawNoGPOrMemoryForm(decodeARM64RawAES, (*arm64Ctx).lowerRawAES),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSM4, (*arm64Ctx).lowerRawSM4),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSM3, (*arm64Ctx).lowerRawSM3),
	arm64RawNoGPOrMemoryForm(decodeARM64RawRDMA, (*arm64Ctx).lowerRawRDMA),
	arm64RawNoGPOrMemoryForm(decodeARM64RawScalarADDP, (*arm64Ctx).lowerRawScalarADDP),
	arm64RawNoGPOrMemoryForm(decodeARM64RawDotProduct, (*arm64Ctx).lowerRawDotProduct),
	arm64RawNoGPOrMemoryForm(decodeARM64RawMatrixMultiply, (*arm64Ctx).lowerRawMatrixMultiply),
	arm64RawNoGPOrMemoryForm(decodeARM64RawTableLookup, (*arm64Ctx).lowerRawTableLookup),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSQRDMULH, (*arm64Ctx).lowerRawSQRDMULH),
	arm64RawNoGPOrMemoryForm(decodeARM64RawMixedSaturatingAdd, (*arm64Ctx).lowerRawMixedSaturatingAdd),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSQDMULH, (*arm64Ctx).lowerRawSQDMULH),
	arm64RawNoGPOrMemoryForm(decodeARM64RawMUL, (*arm64Ctx).lowerRawMUL),
	arm64RawNoGPOrMemoryForm(decodeARM64RawHalvingAddSub, (*arm64Ctx).lowerRawHalvingAddSub),
	arm64RawNoGPOrMemoryForm(decodeARM64RawIntegerCompare, (*arm64Ctx).lowerRawIntegerCompare),
	arm64RawNoGPOrMemoryForm(decodeARM64RawMLS, (*arm64Ctx).lowerRawMLS),
	arm64RawNoGPOrMemoryForm(decodeARM64RawPairwiseAddLong, (*arm64Ctx).lowerRawPairwiseAddLong),
	arm64RawNoGPOrMemoryForm(decodeARM64RawUMULL, (*arm64Ctx).lowerRawUMULL),
	arm64RawNoGPOrMemoryForm(decodeARM64RawAddHighNarrow, (*arm64Ctx).lowerRawAddHighNarrow),
	arm64RawNoGPOrMemoryForm(decodeARM64RawUZP, (*arm64Ctx).lowerRawUZP),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSaturatingShiftNarrow, (*arm64Ctx).lowerRawSaturatingShiftNarrow),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSQSHLU, (*arm64Ctx).lowerRawSQSHLU),
	arm64RawNoGPOrMemoryForm(decodeARM64RawUSHLL, (*arm64Ctx).lowerRawUSHLL),
	arm64RawNoGPOrMemoryForm(decodeARM64RawUMLAL, (*arm64Ctx).lowerRawUMLAL),
	arm64RawNoGPOrMemoryForm(decodeARM64RawDUPElement, (*arm64Ctx).lowerRawDUPElement),
	arm64RawNoGPOrMemoryForm(decodeARM64RawMLA, (*arm64Ctx).lowerRawMLA),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSHA3, (*arm64Ctx).lowerRawSHA3),
	arm64RawNoGPOrMemoryForm(decodeARM64RawLogical, (*arm64Ctx).lowerRawLogical),
	arm64RawNoGPOrMemoryForm(decodeARM64RawModifiedImmediate, (*arm64Ctx).lowerRawModifiedImmediate),
}

func decodeARM64RawVectorFamily(word uint32) (arm64RawFamily, arm64RawContinuationEffects, bool) {
	for _, family := range arm64RawVectorFamilies {
		if effects, ok := family.effects(word); ok {
			return family, effects, true
		}
	}
	return arm64RawFamily{}, arm64RawContinuationEffects{}, false
}
