package plan9asm

// Numerical availability only: the paired whole original opcode owns the
// ambient FP state, precise fault and complete m128 access obligations. No
// backing, caller, frame, native-entry or subsequent-read authority follows.
func x86ResultFourSourceStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86FourSourceProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) || form.memory.Kind == OpFP {
		return false, true
	}
	if form.maskIndex >= 0 {
		mask, valid := amd64ParseKReg(ins.Args[form.maskIndex].Reg)
		if !valid || !state.masks[mask] {
			return false, true
		}
	}
	if !x86ResultReadWithNativeContinuation(ins, form.memory, 16, state, owned, arch, native) {
		return false, true
	}
	required := x86CallerVectorByteMask(form.inputBytes())
	for position := 0; position < 4; position++ {
		if state.vectorBytes(form.sourceBase+position)&required != required {
			return false, true
		}
	}
	destination, _ := amd64VectorRegisterIndex(form.destination.Reg, form.byteWidth())
	old := state.vectorBytes(destination)
	if old&required != required {
		return false, true // .Z still reads the old accumulator in active lanes.
	}
	defined := required
	if form.spec.scalar {
		defined |= old & (0xffff &^ required)
	}
	state.writeVector(destination, form.byteWidth(), defined, false)
	return true, true // Other vectors, GP, FLAGS, DF/ID and K state are unchanged.
}
