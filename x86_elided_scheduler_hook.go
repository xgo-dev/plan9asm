package plan9asm

import "strings"

// Consume only the scheduler hooks which callSym already elides. No callable
// signature, outgoing bytes, result, frame or continuation permission follows.
func (c *amd64Ctx) loweredElidedSchedulerHookStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	if ins.Op != OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym ||
		!strings.HasSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)") || !x86ResultNamedPredicateInstruction(ins) ||
		len(ins.x86SourceStackFP) != 0 || len(ins.x86CallerMemory) != 0 || len(ins.x86FixedLocalMemory) != 0 ||
		ins.x86NumericalRead != nil || ins.x86SDKLiteral != nil {
		return false, false
	}
	name, offset, valid := parseSBRef(ins.Args[0].Sym)
	base, selector, selected := strings.Cut(name, "<")
	if !valid || offset != 0 || strings.Contains(base, ">") || selected && selector != "ABI0>" && selector != "ABIInternal>" {
		return false, false
	}
	original := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
	callee := strings.ReplaceAll(base, "·", ".")
	if !arm64ElidesSchedulerHook(callee) || c.resolve(original) != callee {
		return false, false
	}
	if arch != "amd64" && arch != "386" || state.continuation != nil ||
		state.valueStack != nil && (state.valueStack.invalid || len(state.valueStack.bytes) != 0) {
		return false, true
	}
	// Keep logical FP/AUTO values which were not passed to the hook. Revoke
	// machine facts conservatively, without changing the existing no-op IR.
	state.gp, state.canonicalGP = [16]uint8{}, [16]uint8{}
	state.xmm, state.vectorUpper = [32]uint16{}, [32]uint64{}
	state.nativeMMX, state.masks = [8]uint8{}, [8]bool{}
	state.pointerGP, state.callerAddressGP = [16]bool{}, [16]bool{}
	state.callerAddressOrigin = [16]uint16{}
	state.resultAddressGP = [16]x86ResultSlotAddress{}
	if state.boolFrameGP != nil {
		state.boolFrameGP = new([16]x86ResultSlotAddress)
	}
	state.flags, state.direction = 0, x86ResultDirectionUnknown
	state.predicate, state.bitScanPending = x86ResultPredicate{}, x86ResultBitScanPending{}
	state.gpBits, state.shiftBits = x86ResultGPBits{}, x86ResultShiftBits{}
	state.nativeLEAAddressBits = x86NativeLEAAddressBits{}
	state.stringCount, state.cpuidRootLeaf = x86StringCountUnknown, false
	if state.x87 != nil {
		state.x87.revoke()
	}
	return true, true
}
