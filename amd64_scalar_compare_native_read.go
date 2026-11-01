package plan9asm

// The paired compare/test emitter performs a volatile native read. If it
// continues, the comparison's inputs are numerical and its defined flags are
// available. This does not assert that an address is backed, in bounds, aligned
// or writable; no pointer identity, memory bytes or reusable proof is produced.
func (c *amd64Ctx) scalarCompareNativeResultTransfer(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	if ins.x86NumericalRead != nil {
		return false, false // The immutable source-layout certificate owns this read.
	}
	form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil {
		return false, true
	}
	if form.memory < 0 {
		// The shared ordinary source transfer owns register-only effects,
		// including separately authenticated caller/literal address predicates.
		// A native-memory retry must not intercept those independent roles.
		return false, false
	}
	for index, operand := range form.args {
		if index != form.memory || !x86OrdinaryNativeMemoryOperand(operand, arch) {
			if operand.Kind == OpReg && !state.shapeOnly {
				register, _, valid := x86ResultGP(operand.Reg, int64(form.bits/8), arch)
				if valid && state.pointerGP[register] {
					return false, true
				}
			}
			if !x86ResultRead(operand, int64(form.bits/8), state, owned, arch) {
				return false, true
			}
			continue
		}
		if !x86ResultReadWithNativeGPContinuation(ins, operand, int64(form.bits/8), state, owned, arch) {
			return false, true
		}
	}
	state.flags = x86ByteFlagsAll
	if form.test {
		state.flags &^= x86ByteFlagAF
	}
	return true, true
}

func (c *amd64Ctx) scalarCompareNativeAddress(operand Operand, state *x86ResultState, arch string) bool {
	// This rule deliberately excludes unbound TLS/segments, absolute numerical
	// addresses, unknown GP bases and virtual frame addresses. External SB needs
	// its existing actual-source numerical certificate: a volatile read alone
	// cannot establish that an LLVM global preserves original Go field layout.
	return x86ResultIncomingPointerReadAddressIdentity(operand, state, arch)
}
