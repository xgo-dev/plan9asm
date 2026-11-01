package plan9asm

// This is a lowering-only continuation for the original side-effecting MOVNTI
// opcode. It supplies no numerical bytes, pointer backing, later memory facts,
// frame permission or caller contract. Void/dead stores owe the same inputs.
func x86LoweredMOVNTIResultStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86MOVNTIProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return false, true
	}
	if form.trap {
		return true, true // The independently registered #UD closes control flow.
	}
	if x86LogicalSourceFrameRegister(form.source.Reg, arch) ||
		!x86RegisterAddressedNativeMemoryOperand(form.destination, arch) ||
		!x86ResultIncomingPointerAddressIdentity(form.destination, state, arch) {
		return false, true
	}
	return x86ResultRead(form.source, int64(form.bits/8), state, owned, arch), true
}
