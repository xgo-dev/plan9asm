package plan9asm

// Must-defined DF with an independent value domain. A mixed forward/backward
// join is defined but not a chosen direction. Unknown entry DF stays unknown;
// no ABI, declaration or initialized six-status mask seeds it.
type x86ResultDirection uint8

const (
	x86ResultDirectionUnknown  x86ResultDirection = 0
	x86ResultDirectionForward  x86ResultDirection = 1
	x86ResultDirectionBackward x86ResultDirection = 2
	x86ResultDirectionEither   x86ResultDirection = 3
)

func (direction x86ResultDirection) intersect(other x86ResultDirection) x86ResultDirection {
	if direction == x86ResultDirectionUnknown || other == x86ResultDirectionUnknown {
		return x86ResultDirectionUnknown
	}
	return direction | other
}

func x86ResultDirectionStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	spec, known, err := x86DirectionControlProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	state.direction = x86ResultDirectionForward
	if spec.backward {
		state.direction = x86ResultDirectionBackward
	}
	return true, true
}

// Applied after every independently accepted source transfer, including
// private CALL/stack roles. This never authorizes those operations. Unknown
// physical effects and callee/FLAGS restoration cannot retain a prior DF fact.
func x86ResultDirectionAfter(ins Instr, direction x86ResultDirection) x86ResultDirection {
	if x86MaskLogicalPreservesStorage(ins) || x86EnqueuePreservesStorage(ins) {
		return direction
	}
	if x86RegisterQueryPreservesSourceState(ins) || x86WaitPackagePreservesStorage(ins) || x86PreservesNumericalSourceState(ins) {
		return direction
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.Op == OpCALL {
		return x86ResultDirectionUnknown
	}
	if spec, known := amd64StackWidthSpecs[ins.Op]; known && spec.mode == amd64StackPopFlags {
		return x86ResultDirectionUnknown
	}
	if spec, known := amd64FarReturnSpecs[ins.Op]; known && spec.kind == amd64InterruptReturn {
		return x86ResultDirectionUnknown
	}
	return direction
}

// Only the paired source-flow consumer has a target mode and authenticated
// raw product. Preserve an existing DF fact without making that data-changing
// operation inert or extending the standalone observer's raw-source boundary.
func x86ResultDirectionAfterSource(ins Instr, direction x86ResultDirection, arch string) x86ResultDirection {
	if x86RawCOMISource(ins, arch) {
		return direction // Six scalar status writes do not change the independent DF control.
	}
	if x86RawMULXSource(ins, arch) {
		return direction // The exact integer product does not write DF.
	}
	if x86RawZeroExtendSource(ins, arch) {
		return direction // Exact widening writes no independent DF control.
	}
	if x86RawPermute128Source(ins, arch) {
		return direction // Exact vector selection does not write the independent DF domain.
	}
	if x86FMA3PreservesPrivateSourceState(ins, arch) {
		return direction // The original floating operation does not write DF.
	}
	if x86RawBlendMinposSource(ins, arch) {
		return direction // The exact data selection/reduction has no FLAGS/DF write.
	}
	if x86RawImmediateBlendSource(ins, arch) {
		return direction // Exact immediate selection does not write the independent DF domain.
	}
	if x86RawScalarPrecisionSource(ins, arch) || x86RawScalarFloatIntegerSource(ins, arch) ||
		x86RawPackedPrecisionSource(ins, arch) || x86RawNamedHalfSource(ins, arch) {
		return direction // Native MXCSR effects do not alter the independent DF control.
	}
	if x86RawExplicitMaskMoveSource(ins, arch) {
		return direction // The exact masked move has no FLAGS/DF write.
	}
	if x86RawPackedDotSource(ins, arch) {
		return direction // The exact integer dot operation does not write DF.
	}
	if x86RawUnalignedLoadSource(ins, arch) {
		return direction
	}
	if x86RawIntegerMinMaxSource(ins, arch) {
		return direction // The exact vector operation has no DF effect.
	}
	if x86RawTernaryLogicSource(ins, arch) {
		return direction // The data-changing Boolean operation leaves the existing DF unchanged.
	}
	if x86RawLegacyFloatCompareSource(ins, arch) {
		return direction // MXCSR effects do not write the independent DF control.
	}
	if x86FloatMinMaxPreservesSourceState(ins, arch) {
		return direction // Native MXCSR effects do not change the independent DF input.
	}
	if x86RawPackedConversionSource(ins, arch) || x86RawPackedReductionSource(ins, arch) || x86RawDwordProductResultSource(ins, arch) || x86RawCMOVSource(ins, arch) ||
		x86RawAESSource(ins, arch) || x86RawSHASource(ins, arch) || x86RawVectorTestSource(ins, arch) || x86RawIFMASource(ins, arch) ||
		x86RawQwordLookupSource(ins, arch) || x86RawPackedIntegerCompareSource(ins, arch) ||
		x86RawImmediatePackedCompareSource(ins, arch) || x86RawBroadcastSource(ins, arch) || x86RawCLMULSource(ins, arch) {
		return direction
	}
	return x86ResultDirectionAfter(ins, direction)
}
