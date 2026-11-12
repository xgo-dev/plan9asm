package plan9asm

// The state-bank and memory families below are not exceptions or native calls.
// In particular, "~{memory}" on an inline asm is a compiler ordering barrier,
// not evidence that an instruction stores to arbitrary source stack memory.
var arm64RawStateFamilies = [...]arm64RawFamily{
	arm64RawForm(decodeARM64RawNZCV, (*arm64Ctx).lowerARM64NZCV,
		func(form arm64NZCVForm) arm64RawContinuationEffects {
			reads, writes := form.gpEffects()
			return arm64RawContinuationEffects{gpReads: reads, gpWrites: writes}
		}),
	arm64RawForm(decodeARM64RawDCZVA, (*arm64Ctx).lowerARM64CacheForm,
		func(form arm64CacheForm) arm64RawContinuationEffects {
			index, gp := arm64StackIndex(form.address)
			if !gp || form.address == ZR {
				return arm64RawContinuationEffects{stores: true}
			}
			return arm64RawContinuationEffects{gpReads: arm64RawGPBit(index), stores: true}
		}),
	arm64RawNoGPOrMemoryForm(decodeARM64RawStreamingModeControl, (*arm64Ctx).lowerRawStreamingModeControl),
	arm64RawNoGPOrMemoryForm(decodeARM64RawZAZero, (*arm64Ctx).lowerRawZAZero),
	arm64RawNoGPOrMemoryForm(decodeARM64RawSMEOuterProduct, (*arm64Ctx).lowerRawSMEOuterProduct),
	arm64RawForm(decodeARM64RawSMETileRead, (*arm64Ctx).lowerRawSMETileRead,
		func(form arm64RawSMETileRead) arm64RawContinuationEffects {
			return arm64RawContinuationEffects{gpReads: arm64RawGPBit(form.row)}
		}),
	arm64RawForm(decodeARM64RawSMETileWrite, (*arm64Ctx).lowerRawSMETileWrite,
		func(form arm64RawSMETileRead) arm64RawContinuationEffects {
			return arm64RawContinuationEffects{gpReads: arm64RawGPBit(form.row)}
		}),
	arm64RawForm(decodeARM64RawSMETileMemory, (*arm64Ctx).lowerRawSMETileMemory,
		func(form arm64RawSMETileMemory) arm64RawContinuationEffects {
			return arm64RawContinuationEffects{
				gpReads: arm64RawGPBit(form.row) | arm64RawGPBit(form.base) | arm64RawGPBit(form.offset),
				readsSP: form.base == 31,
				stores:  form.store,
			}
		}),
	arm64RawForm(decodeARM64RawICIVAU, (*arm64Ctx).lowerRawICIVAU,
		func(reg Reg) arm64RawContinuationEffects {
			index, gp := arm64StackIndex(reg)
			if !gp || reg == ZR {
				return arm64RawContinuationEffects{}
			}
			return arm64RawContinuationEffects{gpReads: arm64RawGPBit(index)}
		}),
	arm64RawForm(decodeARM64RawRNDR, (*arm64Ctx).lowerRawRNDR,
		func(form arm64RawRNDR) arm64RawContinuationEffects {
			return arm64RawContinuationEffects{gpWrites: arm64RawGPBit(form.reg)}
		}),
	arm64RawForm(decodeARM64RawCASP, (*arm64Ctx).lowerRawCASP,
		func(form arm64RawCASP) arm64RawContinuationEffects {
			expected := arm64RawGPBit(form.expected) | arm64RawGPBit(form.expected+1)
			newValue := arm64RawGPBit(form.newValue) | arm64RawGPBit(form.newValue+1)
			return arm64RawContinuationEffects{
				gpReads:  expected | newValue | arm64RawGPBit(form.base),
				gpWrites: expected,
				readsSP:  form.base == 31,
				stores:   true,
			}
		}),
}

func decodeARM64RawStateFamily(word uint32) (arm64RawFamily, arm64RawContinuationEffects, bool) {
	for _, family := range arm64RawStateFamilies {
		if effects, ok := family.effects(word); ok {
			return family, effects, true
		}
	}
	return arm64RawFamily{}, arm64RawContinuationEffects{}, false
}
