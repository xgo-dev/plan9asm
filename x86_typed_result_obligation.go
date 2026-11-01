package plan9asm

// Unlike a MOV-store cost selector, a registered numerical family has its own
// whole-result obligation. Missing result stores, unused bool inputs and other
// storage operations cannot substitute for initialized source/result bytes.
// Independently bound entry/storage roles are consumed by the complete cached
// proof; this syntax-only routing decision never grants one.
func x86TypedFPResultNeedsProof(fn Func, sig FuncSig, arch string) bool {
	if arch != "386" && arch != "amd64" {
		return false
	}
	if x86LogicalScalarResultNeedsProof(sig, arch) {
		return true // An absent or partial AX write must not borrow implementation zeroes.
	}
	if x86StaticIntegerResultSourceCandidate(fn, sig, arch) {
		return true
	}
	for _, ins := range x86X87FlowInstructions(fn) {
		if _, known, err := x86X87EnvironmentReadProperties(ins, arch); known && err == nil {
			return true // Dead environment reads retain input and stack obligations for Void.
		}
		if form, known, err := x86X87ValueProperties(ins, arch); known && err == nil &&
			(form.spec.kind == x86X87FloatMove || form.spec.kind == x86X87IntegerMove || form.spec.kind == x86X87Round ||
				form.spec.kind == x86X87ConditionalMove) && (form.memoryBytes() == 10 || x86ResultNamedPredicateInstruction(ins)) {
			return true // Input/control/stack obligations also apply to Void; private slots cannot supply unknown facts.
		}
	}
	opaqueAddressResult := x86OpaqueAddressPointerResultRole(fn, sig, arch)
	for ordinal, ins := range fn.Instrs {
		if form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil && form.memory >= 0 {
			return true // Dead compare/test FLAGS do not remove the original faulting read or its inputs.
		}
		if _, terminal, err := x86UndefinedTrapProperties(ins.Op, ins, arch); terminal && err == nil {
			return true // Only this instruction has no inputs; earlier effects still need complete proof.
		}
		if form, known, err := x86NamedHalfProperties(ins.Op, ins, arch); known && err == nil && !form.undefinedOpcode() {
			return true // Void still consumes active source, merge, mask and native address inputs.
		}
		if _, known, err := x86ExplicitMaskMoveProperties(ins.Op, ins, arch); known && err == nil {
			return true // Dead loads/stores retain actual masks, data and address obligations.
		}
		if form, known, err := x86VSIBProperties(ins, arch); known && err == nil && !form.prefetch {
			return true // Dead indexed accesses retain index, mask, merge/data and address inputs.
		}
		if _, known, err := x86FloatMinMaxProperties(ins, arch); known && err == nil {
			return true // Dead MIN/MAX still consumes actual lane, merge and mask inputs.
		}
		if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known && err == nil && !form.undefinedOpcode() &&
			(ins.x86SourceRaw != nil || ins.x86Encoded ||
				form.ordinaryMemory(ins, arch) && x86ResultNamedPredicateInstruction(ins)) {
			return true // Raw/native move inputs, masks and addresses remain obligations even for Void.
		}
		if form, known, err := amd64ScalarVectorMoveProperties(ins, arch); known && err == nil &&
			(!form.spec.legacy || form.memoryWrite) && !form.spec.rawOnly &&
			(ins.x86SourceRaw != nil || ins.x86Encoded ||
				form.memory >= 0 && x86ScalarVectorMoveOrdinaryMemory(ins.Args[form.memory], form.spec.bits, arch) &&
					x86ResultNamedPredicateInstruction(ins)) {
			return true // Scalar dead reads/writes retain exact active native effects and source bytes.
		}
		if _, known, err := x86DuplicateMoveProperties(ins.Op, ins, arch); known && err == nil {
			return true // Dead duplicate moves still need selected bytes, masks, merges and native accesses.
		}
		if _, known, err := x86MOVBEProperties(ins.Op, ins, arch); known && err == nil {
			return true // Both native directions retain their complete input obligations, including Void.
		}
		if _, known, err := x86TernaryGPProperties(ins.Op, ins, arch); known && err == nil {
			return true // Both actual input words remain mandatory for named/raw dead outputs.
		}
		if _, known, err := x86ADXProperties(ins.Op, ins, arch); known && err == nil {
			return true // Both input words and the selected CF/OF chain remain obligations for raw/named Void.
		}
		if _, known, err := x86MULXProperties(ins.Op, ins, arch); known && err == nil {
			return true // Unknown scratch products stay unknown; observable results and native inputs need complete proof.
		}
		if _, known, err := x86ScalarShiftProperties(ins.Op, ins, arch); known && err == nil {
			return true // A paired ISA choice needs actual inputs; Void/unused bool cannot opt out.
		}
		if _, known, err := x86AccumulatorSignExtendProperties(ins.Op, ins, arch); known && err == nil {
			return true // Raw/named implicit AX inputs remain mandatory even for a dead Void result.
		}
		if _, known, err := x86ImplicitDivideProperties(ins.Op, ins, arch); known && err == nil {
			return true // Trapping division still needs its divisor and complete AX or DX:AX even for Void.
		}
		if form, known, err := x86PackedPhysicalProperties(ins.Op, ins, arch, ""); known && err == nil &&
			(form.spec.family == x86PackedDwordProduct || x86ResultNamedPredicateInstruction(ins)) {
			return true // Dword products also retain the existing raw-input obligation.
		}
		if _, known, err := x86FP16BinaryProperties(ins, arch); known && err == nil {
			return true // Dead raw arithmetic still needs source, merge and mask inputs.
		}
		if _, known, err := amd64FMA3Properties(ins, arch); known && err == nil {
			return true // All three FMA inputs remain mandatory even for dead or zero-masked results.
		}
		if _, known, err := x86FP16ConversionProperties(ins, arch); known && err == nil {
			return true // Raw conversion masks and numerical inputs remain mandatory for Void.
		}
		if _, known, err := x86EnqueueProperties(ins.Op, ins, arch); known && err == nil {
			return true // Void and unused status do not supply either command or device address.
		}
		if _, known, err := x86HardwareRandomProperties(ins.Op, ins, arch); known && err == nil {
			return true // A random write cannot invent a physical stack or an unwritten ABI result, including raw Void sources.
		}
		if _, valid := x86RawVMOVWResultForm(ins, arch); valid {
			return true // Raw GP/X/m16 moves still require inputs and addresses for Void.
		}
		if sig.Ret != Void && x86EndBranchPreservesSourceState(ins) {
			return true // End markers preserve existing result bytes; they never supply an ABI return value.
		}
		if _, known, err := x86FloatingHelperProperties(ins, arch); known && err == nil {
			return true // Dead native floating helpers retain every input, mask and exception obligation.
		}
		if _, known, err := x86SqrtProperties(ins, arch); known && err == nil {
			return true // Dead square roots still consume numerical inputs and masks.
		}
		if _, known, err := x86PackedSADProperties(ins, arch); known && err == nil {
			return true // Dead SAD outputs still need selected input bytes, masks and native addresses.
		}
		if spec, _, known, err := x86ImplicitSystemProperties(ins.Op, ins, arch); known && err == nil && spec.writesCarry {
			return true // Named/raw waits need deadline/control bytes, including Void.
		}
		if form, known, err := x86ScalarShiftProperties(ins.Op, ins, arch); known && err == nil &&
			form.hasMemory() && x86ResultNamedPredicateInstruction(ins) {
			return true // Dead native accesses and undefined W counts remain obligations for Void.
		}
		if _, known, err := x86CPUQueryProperties(ins.Op, ins, arch); known && err == nil {
			return true // Named/raw implicit query inputs remain required even for dead Void outputs.
		}
		if _, known, err := x86BLSProperties(ins.Op, ins, arch); known && err == nil {
			return true // BLS sources remain required for Void, including dead native reads.
		}
		if _, known, err := x86PackedLogicalProperties(ins, arch); known && err == nil {
			return true // Dead logical results cannot excuse actual native inputs or masks.
		}
		if _, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch); known && err == nil {
			return true // EQ/GT share source obligations, not logical writeback or caller authority.
		}
		if _, known, err := x86PackedIntegerAddProperties(ins, arch); known && err == nil {
			return true // Native add inputs/masks remain obligations without a result or unrelated KMOV.
		}
		if _, known, err := x86PackedSubtractProperties(ins, arch); known && err == nil {
			return true // Subtract shares the same whole-source obligation, not add's caller authority.
		}
		if _, known, err := x86ScalarBitFieldProperties(ins.Op, ins, arch); known && err == nil {
			return true // Each family's exact control/source bytes remain required even for dead results.
		}
		if _, known, err := x86BroadcastProperties(ins.Op, ins, arch); known && err == nil {
			return true // Dead scalar/block/mask broadcasts still require their actual input bytes.
		}
		if _, known, err := x86FloatCompareProperties(ins, arch); known && err == nil {
			return true // Dead comparisons still consume real vector/mask inputs and native FP effects.
		}
		if form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, arch); known && err == nil && !form.trap {
			return true // Dead non-temporal accesses still need real memory and complete inputs, including Void.
		}
		if form, known, err := x86MOVNTIProperties(ins.Op, ins, arch); known && err == nil && !form.trap {
			return true // Cache-policy stores retain real address/value inputs even when Void or overwritten.
		}
		if _, known, err := x86ScalarBitCountProperties(ins.Op, ins, arch); known && err == nil &&
			isAMD64MemoryOperand(ins.Args[0]) && x86ResultNamedPredicateInstruction(ins) {
			return true // A dead count still performs its exact native read, including Void.
		}
		if _, known, err := x86ScalarBitScanProperties(ins.Op, ins, arch); known && err == nil {
			return true // Dead scans retain source bytes and addresses, including Void and unused bool.
		}
		if _, known, err := x86NativeMMXInstruction(ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // Actual MMX inputs and the closed x87-mode continuation remain obligations for Void.
		}
		if _, known, err := x86PackedShiftProperties(ins.Op, ins, arch); known && err == nil {
			return true // Native accesses and masks stay obligations even with dead numerical outputs.
		}
		if _, known, err := x86PackedUnpackProperties(ins, arch); known && err == nil {
			return true // Named/physical permutations cannot borrow implementation entry bytes.
		}
		if _, known, err := x86PackedNarrowProperties(ins, arch); known && err == nil {
			return true // Named or physical PACK retains address, mask and result obligations even for Void.
		}
		if _, known, err := x86StackWidthProperties(ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // Private transport must not hide unknown result bytes or unbalanced storage.
		}
		if _, known, err := x86ScalarMemoryRMWProperties(ins.Op, ins, arch); known && err == nil &&
			x86ResultNamedPredicateInstruction(ins) && (ordinal == 0 || fn.Instrs[ordinal-1].Op != "LOCK") {
			return true // Ordinary memory RMW inputs remain obligations even for Void or missing results.
		}
		if _, known, err := x86AHFlagsProperties(ins.Op, ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // Dead AH/FLAGS transfers still need their actual source byte or five flags.
		}
		if _, known, err := x86SignedPackedFloatProperties(ins, arch); known && err == nil {
			return true // Complete conversion inputs stay required for Void without a KMOV routing prerequisite.
		}
		if _, known, err := x86PackedConversionProperties(ins, arch); known && err == nil {
			return true // Named/raw dead conversions still retain all numerical, mask and native access inputs.
		}
		if _, known, err := x86ScalarNativeStoreProperties(ins.Op, ins, arch); known && err == nil &&
			x86ResultNamedPredicateInstruction(ins) {
			return true // Register and immediate stores retain data/address obligations, including Void.
		}
		if _, known, err := x86ScalarStaticStoreProperties(ins.Op, ins, arch); known && err == nil &&
			x86ResultNamedPredicateInstruction(ins) {
			return true // Static syntax still needs complete NUM inputs and actual writable storage for Void.
		}
		if form, known, err := x86GPSIMDTransferProperties(ins, arch); known && err == nil &&
			form.memoryWrite && x86ResultNamedPredicateInstruction(ins) {
			return true // SIMD stores need their actual source bytes and address, including Void.
		}
		if form, known, err := x86InsertExtractProperties(ins, arch); known && err == nil &&
			form.memoryWrite && x86ResultNamedPredicateInstruction(ins) {
			return true // Block and PS scalar stores need selected bytes and addresses even for Void.
		}
		if form, known, err := x86ScalarLaneProperties(ins, arch); known && err == nil &&
			!form.insert && form.memory >= 0 && x86ResultNamedPredicateInstruction(ins) {
			return true // All B/W/D/Q extraction stores retain their selected input bytes, including Void.
		}
		if _, _, known, err := x86OtherFixedVectorValueProperties(ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // Complete value inputs and native addresses stay required without results or masks.
		}
		if _, known, err := x86ConditionalSetProperties(ins.Op, ins, arch); known && err == nil &&
			x86ResultNamedPredicateInstruction(ins) {
			return true // Every conditional byte write consumes actual predicate FLAGS, even for Void.
		}
		if _, known, err := x86MaskValueProperties(ins.Op, ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // KADD/KSHIFT/KUNPCK retain their complete input obligation for Void.
		}
		if _, known, err := x86MaskLogicalProperties(ins.Op, ins, arch); known && err == nil && x86MaskLogicalPreservesStorage(ins) {
			return true // Logical masks retain actual inputs and FLAGS even for dead Void outputs.
		}
		if _, known, err := x86MaskVectorProperties(ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // Register data moves require source values even for dead outputs and Void.
		}
		if amd64MaskMoveOperandsValid(ins, arch) && x86ResultNamedPredicateInstruction(ins) {
			return true // Mask inputs/results cannot borrow zeroed implementation slots, even for Void.
		}
		if form, known, err := x86PackedCompactProperties(ins.Op, ins, arch); known && err == nil &&
			!form.undefinedOpcode() && (x86ResultNamedPredicateInstruction(ins) || x86RawCompactSource(ins, arch)) {
			return true // Named and exact raw compact/expand inputs remain obligations even for Void.
		}
		if _, _, _, known := x86StaticAddressValueMove(ins, arch); known && !opaqueAddressResult {
			return true // The address source cannot hide an unwritten result.
		}
		if x86NamedSegmentMOVNeedsProof(ins, arch) {
			return true // Source/input effects remain mandatory even with no result.
		}
		if _, known, err := x86StringInstructionProperties(ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // Implicit data/address/count/DF inputs remain mandatory, including Void.
		}
		if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); known && err == nil &&
			effect.requiresResultProof {
			return true // Mandatory input checks cannot be bypassed by raw syntax, Void or an absent result layout.
		}
		if x86GPFaultingReadNeedsProof(ins, arch) {
			return true // A dead native read still needs its whole-source input proof.
		}
		if sig.Ret == Void || len(sig.Frame.Results) == 0 {
			continue
		}
		if _, known, err := x86X87WordProperties(ins, arch); known && err == nil && x86ResultNamedPredicateInstruction(ins) {
			return true // Word results need the same whole proof without a GP-to-FP MOV.
		}
	}
	return false
}
