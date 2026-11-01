package plan9asm

import (
	"reflect"
	"strings"
)

// This is a lowering-only numerical availability check. A paired original
// opcode or volatile unaligned load either faults or produces its active
// destination bytes; masked inactive bytes retain their separate rule. It does not
// assert that the pointer is valid, aligned, in bounds, nonaliasing or backed by
// initialized Go storage. Those conditions must not be optimizer assumptions.
//
// The declaration-only observers cannot use this rule: without the paired
// original native opcode emission, their query supplies no such conditional
// result. In particular, this never creates a caller-memory or raw-RET token.
func (c *amd64Ctx) checkLoweredScalarFPResultInitialization() error {
	fn, sig, arch := c.fpScalarSource, c.sig, c.goarch
	rawPermute128 := x86Permute128RawReplayRequired(fn, arch)
	if x86COMIRawReplayRequired(fn, arch) || x86FloatMinMaxRawReplayRequired(fn, arch) || x86ScalarPrecisionRawReplayRequired(fn, arch) ||
		x86ExplicitMaskMoveRawReplayRequired(fn, arch) || x86PackedShiftRawReplayRequired(fn, arch) ||
		x86PackedDotRawReplayRequired(fn, arch) || x86ZeroExtendRawReplayRequired(fn, arch) ||
		x86PackedPrecisionRawReplayRequired(fn, arch) || rawPermute128 {
		if err := fn.x86RawReplay.validate(fn, arch); err != nil {
			return err
		}
	}
	var nativeMMX *x86NativeMMXRegion
	named := true
	for _, ins := range fn.Instrs {
		named = named && x86ResultNamedPredicateInstruction(ins)
	}
	if named {
		var err error
		nativeMMX, err = newX86NativeMMXRegion(fn, c.fpSourceSig, arch, c.targetTriple)
		if err != nil {
			return err
		}
	}
	if owned, err := c.checkCustomHelperBoolSource(); owned || err != nil {
		return err
	}
	if x86StaticIntegerResultSourceCandidate(fn, sig, arch) {
		return c.checkStaticIntegerResultInitialization()
	}
	if fn.x86ContinuationFlow != nil {
		if err := c.checkContinuationResultSource(); err != nil {
			return err
		}
		sig = c.fpSourceSig
	}
	if fn.x86FixedLocal != nil {
		return c.checkFixedLocalResultInitialization()
	}
	if fn.x86SourceStack != nil && fn.x86SourceStack.scalarResult != nil {
		return c.checkSourceStackScalarResultInitialization()
	}
	if calls := fn.x86BoolCalls; calls != nil && calls.registerTail != nil {
		return calls.checkCustomRegisterTail(fn, sig, arch)
	}
	if calls := fn.x86BoolCalls; calls != nil && calls.tail != nil {
		return calls.checkTailTerminal(fn, sig, arch)
	}
	strictErr := checkX86ScalarFPResultInitialization(fn, sig, arch)
	customRegisterBool := arch == "386" && sig.Ret == I1 && len(sig.ArgRegs) != 0
	logicalScalar := x86LogicalScalarResultNeedsProof(sig, arch)
	if customRegisterBool || logicalScalar {
		strictErr = checkX86LogicalRegisterResultInitialization(fn, sig, arch,
			func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
				return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
			}, customRegisterBool, false)
	}
	registerEntry := arch == "amd64" && strings.HasSuffix(fn.Sym, "<ABIInternal>")
	if registerEntry {
		strictErr = checkAMD64RegisterResultInitialization(fn, sig,
			func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
				return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
			})
	}
	if strictErr == nil && nativeMMX == nil {
		// Complete numerical bytes do not authenticate the original source.
		// Keep the existing native/frame owners independent, but apply the
		// same restriction-only replay before ordinary strict success too.
		// This branch returns, so the later paired path never repeats it.
		if len(fn.X86RawText) == 0 && fn.x86SourceStack == nil && fn.x86FixedLocal == nil {
			return x86LoweredNumericalProducerReplay(fn, arch)
		}
		return nil
	}
	if selected, err := c.checkRawLogicalScalarResult(); selected {
		return err
	}
	if selected, err := c.checkRawLiteralResults(); selected {
		return err
	}
	if x86TrapOnlyLogicalFPSourceRole(fn, sig, arch) {
		if err := c.checkTrapOnlyLogicalFPResultInitialization(); err == nil {
			c.fpScalarTrapOnly = true
			return nil
		}
	}
	// Native/raw entry contracts are established before ordinary lowering.
	// Do not let this conditional byte rule create or supplement one.
	if len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil {
		return strictErr
	}
	if err := x86LoweredNumericalProducerReplay(fn, arch); err != nil {
		return err // One restriction-only source check, never an input/native capability.
	}
	boundRawClear := false
	boundRawUnaligned := false
	boundRawConversion := false
	boundRawMinMax := false
	boundRawReduction := false
	boundRawTernary := false
	boundRawFloatMinMax := false
	boundRawScalarPrecision := false
	boundRawExplicitMaskMove := false
	boundRawPackedShift := false
	boundRawPackedDot := false
	boundRawZeroExtend := false
	boundRawPackedPrecision := false
	for _, ins := range fn.Instrs {
		if x86RawMaskMoveSource(ins, arch) {
			continue // Exact mask data retains independent input, native-address and width checks.
		}
		if x86RawNamedHalfSource(ins, arch) {
			continue // One whole-producer replay above; no new value, address or entry fact.
		}
		if x86RawPermute128Source(ins, arch) {
			if !rawPermute128 {
				return strictErr
			}
			continue // The complete replay above grants no missing input or memory fact.
		}
		if x86RawPackedPrecisionSource(ins, arch) {
			if !boundRawPackedPrecision && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawPackedPrecision = true
			continue // Exact source/generation grants no missing FP, mask, merge or memory input.
		}
		if x86RawZeroExtendSource(ins, arch) {
			if !boundRawZeroExtend && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawZeroExtend = true
			continue // Exact source identity supplies no missing address, mask or data bytes.
		}
		if x86RawPackedDotSource(ins, arch) {
			if !boundRawPackedDot && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawPackedDot = true
			continue // Exact generation/replay grants no arithmetic input or memory fact.
		}
		if x86RawPackedShiftSource(ins, arch) {
			if !boundRawPackedShift && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawPackedShift = true
			continue // Exact physical identity grants no count, data, mask, address or entry fact.
		}
		if x86RawExplicitMaskMoveSource(ins, arch) {
			if !boundRawExplicitMaskMove && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawExplicitMaskMove = true
			continue // Exact VEX source grants no mask, address, memory or entry fact.
		}
		if x86RawFloatMinMaxSource(ins, arch) {
			if !boundRawFloatMinMax && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawFloatMinMax = true
			continue // Physical generation supplies no missing inputs, memory or entry role.
		}
		if x86RawScalarPrecisionSource(ins, arch) {
			if !boundRawScalarPrecision && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawScalarPrecision = true
			continue // Exact mode/generation retains every active, merge, mask and native input obligation.
		}
		if x86RawScalarFloatIntegerSource(ins, arch) {
			continue // Whole replay above supplies no pointer, data, MXCSR or native entry fact.
		}
		if x86RawLegacyFloatCompareSource(ins, arch) {
			continue // Exact legacy compare bytes supply no missing input, native entry or backing.
		}
		if x86RawCOMISource(ins, arch) {
			continue // Complete replay above binds the exact comparison, never its input or entry facts.
		}
		if x86RawTernaryLogicSource(ins, arch) {
			if !boundRawTernary && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawTernary = true
			continue // Exact mode/selector/operands supply no entry, pointer or reusable backing.
		}
		if x86RawScalarReciprocalSource(ins, arch) {
			continue // Exact source identity retains scalar data, upper bytes and native m32 obligations.
		}
		if x86RawUnalignedLoadSource(ins, arch) {
			if !boundRawUnaligned && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawUnaligned = true
			continue // Exact original load/replay supplies no pointer or raw-entry permission.
		}
		if x86RawMoveHalfSource(ins, arch) {
			continue // Exact sealed m64 moves grant no missing input, storage or raw-entry fact.
		}
		if x86RawVectorMoveSource(ins, arch) {
			continue // Exact typed moves retain all numerical, mask and native address obligations.
		}
		if x86RawIntegerMinMaxSource(ins, arch) {
			if !boundRawMinMax && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawMinMax = true
			continue // Complete replay and typed shape supply no missing inputs or raw entry.
		}
		if x86RawPackedReductionSource(ins, arch) {
			if !boundRawReduction && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawReduction = true
			continue // Exact selectors, physical mode and native effects remain independent obligations.
		}
		if x86RawCompactSource(ins, arch) {
			continue // Exact compact/expand bytes retain all mask, data and native address obligations.
		}
		if x86RawPackedConversionSource(ins, arch) {
			if !boundRawConversion && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
				return strictErr
			}
			boundRawConversion = true
			continue // Exact physical identity retains every typed input and native MXCSR/access obligation.
		}
		if x86RawPackedIntegerCompareSource(ins, arch) {
			continue // Exact legacy/VEX/EVEX data retains every input, mask and paired native access obligation.
		}
		if x86RawBroadcastSource(ins, arch) {
			continue // Exact scalar/block/K-data source retains every numerical and native E6 input obligation.
		}
		if x86RawBlendMinposSource(ins, arch) {
			continue // Exact raw data retains independent mask, aliases and full native tuple obligations.
		}
		if x86RawImmediateBlendSource(ins, arch) {
			continue // Whole replay retains selector, original mode and every native/source input obligation.
		}
		if x86RawCLMULSource(ins, arch) {
			continue // Exact selector/data identity retains its whole native tuple and independent selected qwords.
		}
		if x86RawImmediatePackedCompareSource(ins, arch) {
			continue // Exact immediate/data identity supplies no entry or missing numerical/memory input.
		}
		if x86RawQwordLookupSource(ins, arch) {
			continue // Complete raw data/control inputs retain their separate memory and result obligations.
		}
		if x86RawVectorTestSource(ins, arch) {
			continue // Exact data tests retain all input bytes and native source accesses.
		}
		if x86RawIFMASource(ins, arch) {
			continue // Exact integer FMA retains its separate accumulator, mask and native-read obligations.
		}
		if x86RawFMA3Source(ins, arch) {
			continue // Whole producer replay and native FMA preserve all three input obligations.
		}
		if x86RawSHASource(ins, arch) {
			continue // Exact SHA bytes retain all source/state and native m128 obligations.
		}
		if x86RawAESSource(ins, arch) {
			continue // Exact integer-crypto data keeps every source and state-byte obligation.
		}
		if x86RawCMOVSource(ins, arch) {
			continue // Exact conditional data retains its own predicate and potential inputs.
		}
		if x86RawMOVBESource(ins, arch) {
			continue // Decoder identity grants neither native input bytes nor a destination pointer.
		}
		if x86RawTernaryGPSource(ins, arch) {
			continue // Exact source identity does not supply numerical inputs or native memory.
		}
		if x86RawADXSource(ins, arch) {
			continue // Only the bound default address mode shares the typed carry chain.
		}
		if x86RawAlternatingFloatSource(ins, arch) {
			continue // Exact original arithmetic retains every real vector and memory input.
		}
		if x86RawMULXSource(ins, arch) {
			continue // Exact identity supplies neither implicit DX nor native address inputs.
		}
		if x86RawScalarObserverSource(ins, arch) {
			continue // Existing typed count/mask effects retain all numerical inputs.
		}
		if x86RawScalarSegmentLoadSource(ins, arch) {
			continue // Paired scalar reads retain hardware segments and exact numerical offsets.
		}
		if x86RawVectorZeroSource(ins, arch) {
			continue // Exact implicit SIMD writes preserve independent native input roles.
		}
		if x86RawBMI2ShiftSource(ins, arch) {
			continue // Exact shifts/rotates retain their complete count/data obligations.
		}
		if x86RawLegacyScalarShiftSource(ins, arch) {
			continue // Exact legacy counts/data retain the paired ISA-outcome and native RMW proof.
		}
		if x86RawAccumulatorSignExtendSource(ins, arch) {
			continue // Exact implicit GP arithmetic preserves its independent input obligations.
		}
		if x86RawDwordProductResultSource(ins, arch) {
			continue // Exact decoded integer inputs retain their own mask/address obligations.
		}
		if _, valid := x86RawVMOVWResultForm(ins, arch); valid {
			continue // Exact GP/X/m16 effects share no raw entry or native frame permission.
		}
		if _, valid := x86RawFP16ConversionSourceForm(ins, arch); valid {
			continue // Exact conversion identity retains independent input and mask obligations.
		}
		if x86RawFP16SqrtSource(ins, arch) {
			continue // Square-root inputs remain guarded by the shared typed byte effect.
		}
		if _, valid := x86RawFP16FMASourceForm(ins, arch); valid {
			continue // FMA retains all three inputs, including a zeroing destination.
		}
		if _, valid := x86RawFP16BinarySourceForm(ins, arch); valid {
			continue // Binary input/merge/upper bytes retain their own typed effect.
		}
		if _, valid := x86EnqueueSourceForm(ins, arch); valid {
			continue // Exact device submission retains its own two-address native effect.
		}
		if x86EndBranchPreservesSourceState(ins) {
			continue // Exact native CET tracking preserves inputs, not memory or entry permissions.
		}
		if ins.x86Encoded || ins.x86RawNearReturn != nil ||
			ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return strictErr
		}
		if ins.x86SourceRaw != nil {
			if x86MaskLogicalPreservesStorage(ins) {
				continue // Exact K-only source has independent mask/FLAGS effects, not memory or entry authority.
			}
			if x86RegisterQueryPreservesSourceState(ins) {
				// Exact original/normalized register producers share their
				// checked inputs/outputs. They add no memory,
				// raw-return, stack or native-entry authority to this continuation.
				continue
			}
			if x86X87RawClearInstruction(ins) {
				if !boundRawClear && (fn.x86RawReplay == nil || fn.x86RawReplay.validate(fn, arch) != nil) {
					return strictErr
				}
				boundRawClear = true
				continue
			}
			// The physical decoder already validated the complete NOP and
			// its prefixes before discarding inert ModRM/SIB address fields.
			// Ordinary padding has no memory, register, FLAGS or entry effect.
			// Preserve the sealed original/normalized identity; no other raw
			// instruction may borrow a named load's conditional result rule.
			if !x86NOPPreservesSourceState(ins) {
				return strictErr
			}
		}
	}
	lockPrefixes := x86ResultSourceLockPrefixes(fn, arch)
	addressBitStores := x86LeafNativeAddressBitStoreScope(fn, c.fpSourceSig, arch)
	stringMemory, err := x86ResultStringMemorySourcePlan(fn, arch)
	if err != nil {
		return err
	}
	ownedVectorReads := c.ownedIndexedVectorReads(fn, c.fpSourceSig, arch)
	transfer := func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
		shiftBits := state.shiftBits
		state.shiftBits = x86ResultShiftBits{} // Only the immediately following instruction may consume it.
		state.loweredStaticReads = c.fpScalarData
		state.goReadOnlyRead = c.goReadOnlyStorage.readFor(ins, arch)
		defer func() { state.loweredStaticReads, state.goReadOnlyRead = nil, nil }()
		keepAddressBits := false
		defer func() {
			if !keepAddressBits {
				state.nativeLEAAddressBits = x86NativeLEAAddressBits{}
			}
		}()
		if accepted, known := x86ResultSDKLiteralStep(ins, state, owned, resultOffset, arch); known {
			return accepted // Consume the exact bound source before an overlapping native-memory family.
		}
		if accepted, known := x86ResultNumericalReadStep(ins, state, owned, resultOffset, arch); known {
			return accepted // A checked mutable SB source keeps its own lifetime and byte effects.
		}
		if operand, width, valid := x86OwnedIndexedVectorReadAt(ownedVectorReads, ordinal, ins); valid {
			// Ordinary private tables never precede complete SDK source owners.
			state.literalMemoryOperand, state.literalMemoryBytes = &operand, width
			defer func() { state.literalMemoryOperand, state.literalMemoryBytes = nil, 0 }()
		}
		if accepted, known := x86ResultImmediateBlendStep(ins, state, owned, arch, true); known {
			return accepted // Legacy Type4 opcode or exact volatile VEX tuple retains dead reads and faults.
		}
		if accepted, known := x86ResultBlendMinposStep(ins, state, owned, arch, true); known {
			return accepted // Legacy original opcodes and VEX whole volatile reads retain exact native faults.
		}
		if c.dataBPSource {
			if accepted, known := x86ResultDataBPStep(ins, state, owned, resultOffset); known {
				return accepted // Source-defined opaque BP, never physical frame or numerical pointer bits.
			}
		}
		if accepted, known := x86ResultXLATStep(ins, state, owned, arch, true); known {
			return accepted // Only the paired exact volatile m8 consumes the unsigned AL index and native BX input.
		}
		if accepted, known := x86ResultAlternatingFloatStep(ins, state, owned, arch, true); known {
			return accepted // The VEX tuple remains observable even when its numerical result is dead.
		}
		if accepted, known := x86ResultRoundStep(ins, state, owned, arch, true); known {
			return accepted // Scalar active bytes and copied upper bytes remain distinct.
		}
		if accepted, known := x86ResultVSIBStep(ins, state, arch, true); known {
			return accepted // Exact indexed continuation; never an ordinary contiguous native tuple.
		}
		if accepted, known := x86ResultFourSourceStep(ins, state, owned, arch, true); known {
			return accepted // One complete original opcode owns its m128 access and sequential native exceptions.
		}
		if accepted, known := x86ResultFMA3Step(ins, state, owned, arch, true); known {
			return accepted // The original FMA retains all three inputs, its exact tuple and native MXCSR effects.
		}
		if accepted, known := x86ResultScalarPrecisionStep(ins, state, owned, arch, true); known {
			return accepted // The paired original scalar conversion retains m32/m64 and MXCSR effects.
		}
		if accepted, known := x86ResultScalarFloatIntegerStepWithRead(ins, state, owned, resultOffset, arch, true); known {
			return accepted // The whole native conversion retains exact scalar reads and MXCSR even for Void.
		}
		if accepted, known := x86ResultNamedHalfStep(ins, state, owned, arch, true); known {
			return accepted // The exact original conversion/store retains MXCSR and active native accesses.
		}
		if accepted, known := x86ResultPackedPrecisionStep(ins, state, owned, arch, true); known {
			return accepted // The paired original packed conversion retains exact E2 reads and MXCSR effects.
		}
		if accepted, known := x86ResultPackedAbsSignStep(ins, state, owned, arch, true); known {
			return accepted // Exact native reads and K inputs remain required for dead packed integer results.
		}
		if accepted, known := x86ResultIntegerMinMaxStep(ins, state, owned, arch, true); known {
			return accepted // The paired E4 reader retains active exact-width volatile faults.
		}
		if accepted, known := x86ResultTernaryLogicContinuationStep(ins, state, owned, arch, true); known {
			return accepted // Exact E4 reads survive constant selectors and dead Boolean results.
		}
		if accepted, known := x86LoweredRawPackedReductionStep(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86ResultPackedReductionStep(ins, state, owned, arch, true); known {
			return accepted // Paired whole native reduction retains exact reads and MXCSR/exception behavior.
		}
		if accepted, known := x86ResultMaskBlendStep(ins, state, owned, arch, true); known {
			return accepted // The shared E4 reader retains exact volatile active-lane accesses.
		}
		if accepted, known := x86ResultPackedDotStep(ins, state, owned, arch, true); known {
			return accepted // Paired E4 dwords retain active volatile reads, even for dead results.
		}
		if accepted, known := x86ResultPermute128Step(ins, state, owned, arch, true); known {
			return accepted // Type6 retains the whole m256 access even for two zero halves.
		}
		if accepted, known := x86ResultElementPermuteStep(ins, state, owned, arch, true); known {
			return accepted // E4NF retains the whole tuple/broadcast even at K=0 or for Void.
		}
		if accepted, known := x86ResultPackedFloatShuffleStep(ins, state, owned, arch, true); known {
			return accepted // Same full E4NF access, with both selected numerical sources.
		}
		if accepted, known := x86ResultNativeLEAAddressBitsStep(ins, state, owned, arch, addressBitStores); known {
			keepAddressBits = accepted
			return accepted
		}
		if accepted, known := x86ResultUnalignedLoadStep(ins, state, owned, arch, true); known {
			return accepted // Only the paired original opcode retains native overfetch and optional #AC.
		}
		if accepted, known := x86LoweredRawVectorMoveStep(ins, state, owned, resultOffset, arch); known {
			return accepted // Only the exact move form shares this lowering-local provenance projection.
		}
		if accepted, known := x86LoweredScalarVectorMoveMemoryStep(ins, state, owned, resultOffset, arch); known {
			return accepted // Exact active volatile m32/m64, without a reusable pointee fact.
		}
		if accepted, known := x86ResultScalarReciprocalStep(ins, state, owned, arch, true); known {
			return accepted // Actual scalar estimate keeps the independent exact m32 access and MXCSR contract.
		}
		if accepted, known := x86ResultPackedReciprocalStep(ins, state, owned, arch, true); known {
			return accepted // Only the paired original packed opcode owns its native access and alignment fault.
		}
		if accepted, known := x86ResultLegacyScalarMoveStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted // Only the paired exact volatile legacy m32/m64 read supplies its conditional scalar bytes.
		}
		if accepted, known := x86ResultSegmentQueryStep(ins, state, owned, arch, true); known {
			return accepted // Paired exact volatile m16; no backing or reusable read permission.
		}
		if accepted, known := x86ResultMoveHalfStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted // Paired volatile m64 and selected halves preserve independent native inputs.
		}
		if accepted, known := x86LoweredADXResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredMULXResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted // Exact native read, implicit DX and both products; no FLAGS write.
		}
		if accepted, known := x86LoweredTernaryGPResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredMOVBEResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredRawScalarObserverStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredVectorZeroResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredBMI2ShiftResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredScalarShiftChoiceStep(ins, state, owned, resultOffset, arch); known {
			return accepted // Only this producer-specific emitter materializes finite ISA-undefined outputs.
		}
		if accepted, known := x86LoweredAccumulatorSignExtendResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredImplicitDivideStep(ins, state, owned, arch); known {
			return accepted // Only the original native #DE/access emitter supplies this continuation.
		}
		if accepted, known := x86LoweredImplicitMultiplyNativeRead(ins, state, owned, resultOffset, arch); known {
			return accepted // Exact volatile input, with the existing implicit outputs and CF/OF only.
		}
		if accepted, known := x86LoweredExplicitIMULNativeRead(ins, state, owned, resultOffset, arch); known {
			return accepted // The same exact native reader retains two/three-operand input roles.
		}
		if accepted, known := x86LoweredDwordProductResultStep(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredPackedConversionResultStep(ins, state, owned, arch); known {
			return accepted // The complete original conversion is still emitted, including dead native effects.
		}
		if accepted, known := x86LoweredRawVMOVWResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredFP16ConversionStep(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredFP16FMAStep(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredFP16BinaryStep(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredEnqueueResultStep(ins, state, arch); known {
			return accepted
		}
		if accepted, known := nativeMMX.transfer(ordinal, ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredNativeMXCSRStep(ins, state, arch); known {
			return accepted
		}
		if accepted, known := c.scalarStaticAddressValueTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := c.scalarStaticMoveTransfer(ins, state, owned, arch); known {
			return accepted // Exact owned writable bytes, never an external symbol or pointer-as-NUM grant.
		}
		if accepted, known := c.scalarStaticRMWTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := c.scalarStaticExchangeTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := stringMemory.transfer(ordinal, ins, state, arch); known {
			return accepted
		}
		if ins.Op == "LOCK" {
			prefix, bound := lockPrefixes[ordinal]
			return bound && reflect.DeepEqual(prefix, ins)
		}
		if boundRawClear && x86X87RawClearInstruction(ins) {
			return x86ResultX87BoundRawClear(ins, state, owned, resultOffset, arch)
		}
		if accepted, known := c.x87EnvironmentReadResultStep(ins, state, arch); known {
			return accepted
		}
		if accepted, known := c.x87NativeFloatingMoveResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredStackNativeRead(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredStackNativeStore(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := c.x87HardwareControlResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted // The same actual hardware emitter writes the full i16.
		}
		if accepted, known := c.x87HardwareRoundingResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted // No ambient environment fact reaches the standalone query.
		}
		if accepted, known := x86LoweredCompareExchangeResultStepWithAddressBits(ins, state, owned, arch, addressBitStores); known {
			return accepted
		}
		if accepted, known := x86LoweredExchangeResultStepWithAddressBits(ins, state, owned, arch, addressBitStores); known {
			return accepted
		}
		if accepted, known := x86LoweredCRC32NativeRead(ins, state, owned, resultOffset, arch); known {
			return accepted // The same typed emitter retains the exact volatile source read.
		}
		if accepted, known := x86LoweredScalarBitCountNativeRead(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86ResultBitScanStepWithRead(ins, state, owned, arch, true); known {
			return accepted // The paired scan emitter retains its exact volatile source read.
		}
		if accepted, known := x86ResultScalarBitFieldStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted
		}
		if accepted, known := x86LoweredBLSNativeRead(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86ResultNonTemporalVectorStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted
		}
		if accepted, known := x86LoweredMOVNTIResultStep(ins, state, owned, arch); known {
			return accepted // The original opcode retains cache policy and mandatory native write/faults.
		}
		if accepted, known := x86ResultFloatCompareStep(ins, state, owned, arch, true); known {
			return accepted
		}
		if accepted, known := x86ResultExplicitMaskMoveStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted // The whole original mask move retains active memory faults and writes.
		}
		if accepted, known := x86ResultImplicitMaskMoveStep(ins, state, arch, true); known {
			return accepted // Preserve the original implicit address and non-temporal access, including zero masks.
		}
		if accepted, known := x86ResultFloatingHelperStep(ins, state, owned, arch, true); known {
			return accepted // The complete native opcode retains MXCSR, exceptions and masked accesses.
		}
		if accepted, known := x86ResultSqrtStep(ins, state, owned, arch, true); known {
			return accepted // The paired native opcode retains scalar/packed MXCSR effects.
		}
		if accepted, known := x86LoweredRawCOMIStep(ins, state, owned, arch); known {
			return accepted // Only the bound original opcode owns this local numerical read.
		}
		if accepted, known := x86ResultCOMIStepWithRead(ins, state, owned, arch, true); known {
			return accepted // The original scalar comparison retains exact read and MXCSR effects.
		}
		if accepted, known := x86ResultSignedIntegerFloatStepWithRead(ins, state, owned, arch, true); known {
			return accepted // The same typed emitter retains an exact volatile source read.
		}
		if accepted, known := x86ResultUnsignedIntegerFloatStep(ins, state, owned, arch, true); known {
			return accepted // The original EVEX opcode owns exact reads, MXCSR and precision exceptions.
		}
		if accepted, known := x86ResultSignedPackedFloatStep(ins, state, owned, arch, true); known {
			return accepted // The original native opcode retains rounding, exception and memory effects.
		}
		if accepted, known := x86ResultPackedConversionStepWithRead(ins, state, owned, arch, true); known {
			return accepted // The paired conversion retains its exact access and MXCSR effects.
		}
		if form, known, err := x86FloatAddSubProperties(ins, arch); known {
			return err == nil && x86ScalarFPFloatBinaryTransferWithRead(ins, form.x86FloatBinaryForm, state, owned, arch, true)
		}
		if form, known, err := x86FloatMulDivProperties(ins, arch); known {
			return err == nil && x86ScalarFPFloatBinaryTransferWithRead(ins, form.x86FloatBinaryForm, state, owned, arch, true)
		}
		if accepted, known := x86ResultFloatMinMaxStep(ins, state, owned, arch, true); known {
			return accepted
		}
		if accepted, known := x86ResultPackedStringStepWithRead(ins, state, owned, arch, true); known {
			return accepted // Paired emitter retains the full volatile m128 read.
		}
		if accepted, known := x86ResultPackedZeroExtendStep(ins, state, owned, arch, true); known {
			return accepted
		}
		if accepted, known := x86ResultPackedSignExtendStep(ins, state, owned, arch, true); known {
			return accepted // Named SX shares exact E5 reads, never the separate raw ZX identity.
		}
		if accepted, known := x86ResultByteShuffleStepWithRead(ins, state, owned, arch, true); known {
			return accepted // Same full-tuple E4NF read or original legacy m128 opcode.
		}
		if accepted, known := x86ResultImmediateShuffleStepWithRead(ins, state, owned, arch, true); known {
			return accepted // The paired full tuple or m32 read survives zero masks and dead results.
		}
		if accepted, known := x86ResultPackedAlignStep(ins, state, owned, arch, true); known {
			return accepted // Full E4NF tuples and the original legacy alignment/fault opcode.
		}
		if accepted, known := x86ResultLegacyIntegerNativeReadStep(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, recognized := x86LoweredBlockNativeMemory(ins, state, owned, resultOffset, arch); recognized {
			return accepted
		}
		if accepted, recognized := x86LoweredScalarExtensionRead(ins, state, owned, resultOffset, arch); recognized {
			return accepted
		}
		if accepted, known := x86LoweredCMOVResultStep(ins, state, owned, resultOffset, arch); known {
			return accepted // The complete source read remains unconditional, regardless of the predicate.
		}
		if accepted, recognized := x86LoweredScalarNativeLoad(ins, state, owned, resultOffset, arch); recognized {
			return accepted
		}
		if accepted, recognized := x86LoweredScalarNativeStoreWithAddressBits(ins, state, owned, arch, addressBitStores); recognized {
			return accepted
		}
		if accepted, recognized := x86LoweredScalarMemoryRMW(ins, state, owned, arch); recognized {
			return accepted
		}
		if accepted, known := x86LoweredScalarShiftMemory(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		if accepted, known := x86MaskMoveResultStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted // The same KMOV emitter retains the complete volatile native width.
		}
		if accepted, known := x86LoweredNativeConditionalSet(ins, state, arch); known {
			return accepted // The same typed SETcc emitter preserves its exact volatile byte write.
		}
		if accepted, known := x86LoweredIFMAStep(ins, state, owned, arch); known {
			return accepted // The typed emitter retains exact guarded qword reads and EVEX upper-zeroing.
		}
		if accepted, known := x86ResultQwordLookupStep(ins, state, owned, arch, true); known {
			return accepted // E4 controls and E4NF qword data retain their separate native access shapes.
		}
		if accepted, known := x86LoweredFixedVectorNativeRead(ins, state, owned, arch); known {
			return accepted // The typed emitter retains full E4NF or guarded E4 native accesses.
		}
		if accepted, known := x86ResultSADStep(ins, state, owned, arch, true); known {
			return accepted // The same SAD emitter retains the full tuple and legacy m128 opcode.
		}
		if accepted, known := x86ResultSHAStep(ins, state, owned, arch, true); known {
			return accepted // Native m128 keeps the original opcode, including dead-result faults.
		}
		if accepted, known := x86LoweredAESResultStep(ins, state, owned, arch); known {
			return accepted // Exact legacy opcodes and vector volatile reads retain the full source tuple.
		}
		if accepted, known := x86LoweredVectorTestResultStep(ins, state, owned, arch); known {
			return accepted // One original memory opcode retains the entire read and captures its FLAGS.
		}
		if accepted, known := x86ResultPackedNarrowStep(ins, state, owned, arch, true); known {
			return accepted // The same emitter retains the complete E4NF tuple or original legacy opcode.
		}
		if accepted, known := x86ResultSingleSourceNarrowStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted
		}
		if accepted, known := x86LoweredRawPackedShiftStep(ins, state, owned, arch); known {
			return accepted // Only the exact sealed shift projects onto the existing typed byte effect.
		}
		if accepted, known := x86ResultPackedShiftStepWithRead(ins, state, owned, arch, true); known {
			return accepted // Uniform m128, E4NF tuples and guarded E4 reads retain their independent shapes.
		}
		if accepted, known := x86ResultPackedUnpackStepWithRead(ins, state, owned, arch, true); known {
			return accepted // Unpack retains the full E4NF tuple even with zero masks or dead results.
		}
		if accepted, known := x86ResultDuplicateMoveStep(ins, state, owned, arch, true); known {
			return accepted // Duplicate selectors retain exact E4NF/E5NF tuples and legacy alignment faults.
		}
		if accepted, known := x86ResultVectorArithmeticStepWithRead(ins, state, owned, arch, true); known {
			return accepted // The same add/sub emitter retains exact E4 reads and inactive-lane suppression.
		}
		if accepted, known := x86LoweredPackedIntegerCompareStep(ins, state, owned, arch); known {
			return accepted // The exact original form shares only the existing vector/K-result and E4 effects.
		}
		if accepted, known := x86LoweredImmediatePackedCompareStep(ins, state, owned, arch); known {
			return accepted // Original raw selectors retain their complete paired E4 input effects.
		}
		if accepted, known := x86ResultVectorCompareStepWithRead(ins, state, owned, arch, true); known {
			return accepted // Complete vector/K-result compares retain their exact native source accesses.
		}
		if accepted, known := x86ResultPackedTestMaskStep(ins, state, owned, arch, true); known {
			return accepted // Only the paired original E4 accesses supply memory-derived K values.
		}
		if accepted, known := x86LoweredRawBroadcastStep(ins, state, owned, arch); known {
			return accepted // Exact raw scalar/block/K-data forms share only their paired typed E6 effects.
		}
		if accepted, known := x86LoweredCLMULStep(ins, state, owned, arch); known {
			return accepted // Original legacy opcode or whole volatile vector tuple retains every native read.
		}
		if len(ins.Args) != 0 && ins.Args[0].Kind == OpMem && ins.Args[0].Mem.Sym == "" {
			if accepted, known := x86ResultBroadcastStepWithRead(ins, state, owned, arch, true); known {
				return accepted // Only scalar/block native reads need this paired E6 continuation.
			}
		}
		if form, known, err := x86PackedLogicalProperties(ins, arch); known {
			// Only the paired emitter supplies these conditional native values.
			// Standalone queries and physical MMX keep their separate contracts.
			if err != nil || !x86ScalarFPLogicalTransferWithRead(ins, form, state, owned, arch, true) {
				return false
			}
			if extra := shiftBits.definedBytes(ins, form, c.fpShiftLiterals, arch); extra != 0 {
				destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
				state.writeVector(destination, form.byteWidth, state.vectorBytes(destination)|extra, form.legacy)
			}
			return true
		}
		if accepted, recognized := x86LoweredScalarArithmeticNativeRead(ins, state, owned, resultOffset, arch); recognized {
			return accepted
		}
		if accepted, known := c.scalarPackedLogicalFPWriteTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := c.scalarPSLogicalFPWriteTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := c.scalarBitTestFPShadowTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86LoweredNativeBitTest(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, recognized := x86ResultScalarLaneStepWithRead(ins, state, owned, resultOffset, arch, true); recognized {
			return accepted
		}
		if form, known, err := x86GPSIMDTransferProperties(ins, arch); known && err == nil && form.memory >= 0 {
			return x86ResultGPSIMDTransferWithNativeMemory(ins, form, state, owned, resultOffset, arch, true)
		}
		if accepted, known := c.scalarCompareNativeResultTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86ResultCompactExpandMemoryStep(ins, state, owned, resultOffset, arch, true); known {
			return accepted // Same guarded native emitter; public observers keep logical-only memory.
		}
		if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known && err == nil &&
			form.ordinaryMemory(ins, arch) && x86ResultNamedPredicateInstruction(ins) &&
			(form.memory == 0 && x86ResultIncomingPointerReadAddressIdentity(ins.Args[0], state, arch) ||
				form.memoryWrite && x86ResultIncomingPointerAddressIdentity(ins.Args[form.memory], state, arch)) {
			// The emitter preserves the original aligned opcode, or the
			// unaligned full/guarded tuple with volatile accesses. If it continues,
			// active bytes are numerical; inactive bytes still require the
			// typed merge/zero rule. No pointer validity is asserted.
			return x86ResultPackedVectorMoveTransfer(ins, form, state, owned, resultOffset, arch, true)
		}
		form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch)
		if known && err == nil && form.memoryWrite && x86ResultNamedPredicateInstruction(ins) &&
			form.destination.Kind == OpMem && form.destination.Mem.Sym == "" &&
			x86OrdinaryNativeMemoryOperand(form.destination, arch) {
			// All seven whole128 legacy names retain their exact native
			// store opcode and its alignment/fault contract. This consumes
			// numerical source bytes plus an incoming-pointer address only;
			// no logical storage, validity, extent or later-read fact follows.
			return x86ResultRead(form.source, 16, state, owned, arch) &&
				x86ResultIncomingPointerAddressIdentity(form.destination, state, arch)
		}
		if accepted, known := x86LoweredLegacyPackedMoveRead(ins, state, owned, resultOffset, arch); known {
			return accepted
		}
		next := state.clone()
		// A reaching-state clone deliberately drops temporary readers.
		// This isolated attempt is still inside the same lowering transfer.
		next.loweredStaticReads = state.loweredStaticReads
		next.goReadOnlyRead = state.goReadOnlyRead
		if x86ScalarFPResultTransfer(ins, &next, owned, resultOffset, arch) {
			*state = next
			return true
		}
		if accepted, known := x86ResultUnusedFPAddressStep(ins, state, owned, resultOffset, arch); known {
			return accepted // Mapped logical storage only; no initialized address bits.
		}
		if accepted, known := x86ResultUnknownSBAddressStep(ins, state, arch); known {
			return accepted // Address calculation only; written address bits stay unknown.
		}
		return x86LoweredPureGPUnknownTransfer(ins, state, arch)
	}
	if registerEntry {
		return checkAMD64RegisterResultInitialization(fn, sig, transfer)
	}
	if customRegisterBool || logicalScalar {
		return checkX86LogicalRegisterResultInitialization(fn, sig, arch, transfer, customRegisterBool, true)
	}
	if err := checkX86ABI0ResultInitializationWithTrapOnly(fn, sig, arch, transfer, true, false, true); err != nil {
		return err
	}
	c.nativeMMXRegion = nativeMMX
	return nil
}

// Only the lowering observer may consume a paired exact-width volatile load
// from a typed emitter. Continued execution supplies active numerical source
// bytes, even if a later selector discards them; masked inactive bytes keep
// the family's independent merge/zero rule.
// Family-specific lane/zero/alias effects remain independent. This grants no
// validity, bounds, write, frame, caller or raw-entry permission.
func x86ResultReadWithNativeContinuation(ins Instr, source Operand, width int64, state *x86ResultState, owned []bool, arch string, conditionalNativeRead bool) bool {
	return x86ResultReadWithNativeAddress(ins, source, width, state, owned, arch, conditionalNativeRead, false)
}

// Scalar GP forms independently normalize named segment syntax. Vector and
// raw consumers keep their existing continuation and source domains.
func x86ResultReadWithNativeGPContinuation(ins Instr, source Operand, width int64, state *x86ResultState, owned []bool, arch string) bool {
	return x86ResultReadWithNativeAddress(ins, source, width, state, owned, arch, true, true)
}

func x86ResultReadWithNativeAddress(ins Instr, source Operand, width int64, state *x86ResultState, owned []bool, arch string, conditionalNativeRead, segmentRead bool) bool {
	if x86ResultRead(source, width, state, owned, arch) {
		return true
	}
	if !(conditionalNativeRead && source.Kind == OpMem && source.Mem.Sym == "" &&
		ins.x86NumericalRead == nil && !ins.x86Encoded && ins.x86SourceRaw == nil && ins.x86RawNearReturn == nil &&
		ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride && ins.x86SegmentPrefix == 0 &&
		x86OrdinaryNativeMemoryOperand(source, arch)) {
		return false
	}
	if segmentRead {
		if accepted, segment := x86ResultNativeSegmentAddress(ins, source, state, owned, arch); segment {
			return accepted
		}
	}
	return x86ResultIncomingPointerReadAddressIdentity(source, state, arch)
}
