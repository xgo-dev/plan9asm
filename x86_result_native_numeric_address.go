package plan9asm

// Only an already selected native emitter may consume these numerical address
// bits. A successful volatile access initializes its result, not its pointee,
// and creates no logical pointer, extent, caller or reusable storage fact.
func x86ResultNativeNumericAddress(arg Operand, state *x86ResultState, arch string) bool {
	if arg.Kind != OpMem || arg.Mem.Sym != "" || arg.Mem.OffRaw != "" ||
		arg.Mem.Segment != "" || arg.Mem.IndexExt != "" ||
		!x86OrdinaryNativeMemoryOperand(arg, arch) {
		return false
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
