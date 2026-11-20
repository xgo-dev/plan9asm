package plan9asm

import "reflect"

func x86RawBMI2ShiftSource(ins Instr, arch string) bool {
	form, known, err := x86ScalarShiftProperties(ins.Op, ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && form.bmi2 && origin != nil && origin.op == ins.Op &&
		reflect.DeepEqual(origin.args, ins.Args) && origin.vectorBytes == ins.x86VectorBytes &&
		ins.x86RawNearReturn == nil && ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride &&
		ins.x86SegmentPrefix == 0 && !ins.x86RIPLiteral && ins.x86NumericalRead == nil
}

// Exact original operands permit only this paired numerical transfer. Native
// reads still need the same incoming address and exact volatile emitter; raw
// entry, frame, backing and standalone declaration queries gain no permission.
func x86LoweredBMI2ShiftResultStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, _ := x86ScalarShiftProperties(ins.Op, ins, arch)
	if !known || !form.bmi2 || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if !x86RawBMI2ShiftSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	if accepted, known := x86LoweredScalarShiftMemory(local, state, owned, resultOffset, arch); known {
		return accepted, true
	}
	next := state.clone()
	if x86ResultTransfer(local, &next, owned, resultOffset, arch) {
		*state = next
		return true, true
	}
	// The existing nontrapping GP domain may retain a dead unknown result.
	// It never initializes that result or grants a subsequent observable use.
	return x86LoweredPureGPUnknownTransfer(local, state, arch), true
}
