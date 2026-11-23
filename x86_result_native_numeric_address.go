package plan9asm

// A paired native emitter can consume one numerical value in both SIB
// fields. Other addresses retain their existing incoming-pointer proof.
func x86ResultPairedNativeAddress(ins Instr, arg Operand, state *x86ResultState, arch string, commutedRead bool) bool {
	return x86ResultIncomingPointerAddress(arg, state, arch, commutedRead) ||
		arg.Kind == OpMem && arg.Mem.Index != "" && arg.Mem.Base == arg.Mem.Index &&
			x86ResultNamedPredicateInstruction(ins) && ins.x86NumericalRead == nil &&
			x86MemoryRegisterEncodingValid(arg.Mem, arch) &&
			x86ResultNativeNumericAddress(arg, state, arch)
}

// The same register may supply both a data input and the address base of an
// already paired instruction. All effective address bytes must reach the use.
func x86ResultSharedNumericalAddress(ins Instr, address Operand, state *x86ResultState,
	arch string, numericalInputs ...Operand) bool {
	if len(numericalInputs) == 0 || address.Kind != OpMem || !x86ResultNamedPredicateInstruction(ins) ||
		ins.x86NumericalRead != nil || !x86MemoryRegisterEncodingValid(address.Mem, arch) ||
		address.Mem.Index == "" && address.Mem.Scale != 0 {
		return false
	}
	for _, operand := range numericalInputs {
		if operand.Kind != OpReg {
			continue
		}
		if root, valid := x86CallerGP(operand.Reg); valid && root == address.Mem.Base {
			return x86ResultNativeNumericAddress(address, state, arch)
		}
	}
	return false
}

// Only an already selected native emitter may consume these numerical address
// bits. A successful volatile access initializes its result, not its pointee,
// and creates no logical pointer, extent, caller or reusable storage fact.
func x86ResultNativeNumericAddress(arg Operand, state *x86ResultState, arch string) bool {
	if arg.Kind != OpMem || arg.Mem.Sym != "" || arg.Mem.OffRaw != "" ||
		arg.Mem.Segment != "" || arg.Mem.IndexExt != "" ||
		!x86OrdinaryNativeMemoryOperand(arg, arch) {
		return false
	}
	if x86AbsoluteMemoryRef(arg.Mem) {
		return x86MemoryDisplacementValid(arg.Mem.Off, arch)
	}
	word := x86ResultPointerWord(arch)
	base, mask, valid := x86ResultGP(arg.Mem.Base, word, arch)
	if !valid || state.gp[base]&mask != mask {
		return false
	}
	if arg.Mem.Index == "" {
		return true
	}
	index, mask, valid := x86ResultGP(arg.Mem.Index, word, arch)
	return valid && state.gp[index]&mask == mask
}
