package plan9asm

// Conditional continuation of the complete native BIT emitter. The exact
// volatile word read/write and signed dynamic bit-string addressing remain
// observable. This supplies CF, not reusable memory or address authority.
func x86LoweredNativeBitTest(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86BitTestProperties(ins.Op, ins, arch)
	if !known || err != nil || form.destination.Kind != OpMem {
		return false, false
	}
	if !x86ResultNamedPredicateInstruction(ins) ||
		!x86ResultNativeRMWAddress(ins, form.destination, state, owned, arch) ||
		!x86ResultRead(form.index, int64(form.bits/8), state, owned, arch) {
		return false, true
	}
	effect, _, _ := x86TypedBitTestByteEffect(ins.Op, ins, arch)
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true // No GP, vector, DF or logical storage changes.
}

// Only the paired scalar/bit-string emitter consumes this address. FS/GS
// contributes its actual hardware base, never an AS0 pointer or storage fact.
// A named GP offset still needs full numerical bytes; ordinary RMW addresses
// keep their stricter incoming-pointer-base rule and cannot commute operands.
func x86ResultNativeRMWAddress(ins Instr, address Operand, state *x86ResultState, owned []bool, arch string) bool {
	if accepted, segment := x86ResultNativeSegmentAddress(ins, address, state, owned, arch); segment {
		return accepted
	}
	return x86ResultIncomingPointerAddressIdentity(address, state, arch)
}

// Named hardware segments supply an actual base independently of numerical
// GP address roles. Only an explicit offset consumes NUM; no storage follows.
func x86ResultNativeSegmentAddress(ins Instr, address Operand, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	projected, segment, err := x86NamedSegmentMemorySource(ins, address, arch)
	if !segment {
		return false, false
	}
	if err != nil || !x86OrdinaryNativeMemoryOperand(projected, arch) {
		return false, true
	}
	base := projected.Mem.Base
	if base == "" {
		return true, true
	}
	word := x86ResultPointerWord(arch)
	index, _, valid := x86ResultGP(base, word, arch)
	return valid && (state.shapeOnly || !state.pointerGP[index]) &&
		x86ResultRead(Operand{Kind: OpReg, Reg: base}, word, state, owned, arch), true
}
