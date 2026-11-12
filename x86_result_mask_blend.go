package plan9asm

// A paired E4 load either supplies the selected native bytes or faults. Its
// mask suppresses only inactive lanes; this never creates native address,
// FP/AUTO, raw-entry or caller storage permissions.
func x86ResultMaskBlendStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86MaskBlendProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	if form.mask >= 0 {
		mask, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[mask] {
			return false, true
		}
	}
	width := int64(form.byteWidth)
	firstWidth := width
	if form.memory >= 0 {
		firstWidth = int64(form.memoryBytes)
	}
	first := ins.Args[form.first]
	firstKnown := x86ResultPackedVectorRead(first, firstWidth, state, owned, arch)
	if !firstKnown && nativeRead && first.Kind != OpReg {
		firstKnown = x86ResultReadWithNativeContinuation(ins, first, firstWidth, state, owned, arch, true)
	}
	if !firstKnown || form.mask >= 0 && !form.zeroing &&
		!x86ResultPackedVectorRead(ins.Args[form.second], width, state, owned, arch) {
		return false, true
	}
	destination, valid := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	if !valid {
		return false, true
	}
	state.writeVector(destination, form.byteWidth, ^uint64(0), false)
	return true, true
}
