package plan9asm

// The existing complete CMOV grammar supplies widths and exact predicate
// dependencies. Its paired lowerer always emits the full volatile read,
// including false predicates and dead outputs. Continuing past that access
// produces NUM, not backing, bounds, pointer or native-entry authority.
func x86RawCMOVSource(ins Instr, arch string) bool {
	_, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

func x86LoweredCMOVResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ConditionalMoveProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	named := x86ResultNamedPredicateInstruction(ins)
	if named && form.source.Kind != OpMem {
		return false, false // The existing strict transfer owns named register data.
	}
	if !named {
		if !x86RawCMOVSource(ins, arch) {
			return false, true
		}
		// Project only this authenticated operation, never its original file
		// or caller/source-stack metadata. Raw entry and memory stay separate.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	if form.source.Kind != OpReg && (form.source.Kind != OpMem || form.source.Mem.Sym != "" ||
		!x86OrdinaryNativeMemoryOperand(form.source, arch)) {
		return false, false // Logical fields and independently bound sources keep their own consumers.
	}
	width := int64(form.bits / 8)
	required := x86ByteConditionFlags(form.condition)
	destination, _, valid := x86ResultGP(form.destination.Reg, width, arch)
	if !valid || state.pointerGP[destination] || !x86ResultNamedPredicateInstruction(ins) ||
		required == 0 || state.flags&required != required ||
		!x86ResultRead(form.destination, width, state, owned, arch) ||
		!x86ResultReadWithNativeContinuation(ins, form.source, width, state, owned, arch, true) {
		return false, true
	}
	if form.source.Kind == OpReg {
		source, _, valid := x86ResultGP(form.source.Reg, width, arch)
		if !valid || state.pointerGP[source] {
			return false, true
		}
	}
	return x86ResultStore(form.destination, width, state, owned, resultOffset, arch), true
}
