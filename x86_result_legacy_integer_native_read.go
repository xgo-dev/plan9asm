package plan9asm

// Only the paired lowering observer may use this conditional result rule.
// The complete legacy add/subtract form selects an original sideeffect m128
// opcode, preserving its alignment and dead-fault effects. Continued execution
// produces numerical result bytes; it proves no pointer extent or alignment.
func x86ResultLegacyIntegerNativeReadStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, registered, err := x86LegacyIntegerArithmeticProperties(ins.Op, ins, arch)
	if !registered || err != nil {
		return false, registered
	}
	if form.mmx || !form.legacy || form.byteWidth != 16 || form.memory != 0 || form.source.Kind != OpMem || form.source.Mem.Sym != "" {
		return false, false // Existing register, static and virtual roles stay separate.
	}
	if !x86OrdinaryNativeMemoryOperand(form.source, arch) || ins.x86NumericalRead != nil ||
		ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false, true
	}
	if !x86ResultRead(form.destination, 16, state, owned, arch) ||
		!x86ResultReadWithNativeContinuation(ins, form.source, 16, state, owned, arch, true) {
		return false, true
	}
	// The shared legacy byte store preserves higher physical vector bytes;
	// neither input is read after this write. These opcodes leave FLAGS intact.
	return x86ResultStore(form.destination, 16, state, owned, resultOffset, arch), true
}
