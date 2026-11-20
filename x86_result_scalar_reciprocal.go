package plan9asm

// A scalar estimate consumes only low32 and copies upper96 independently.
// An unknown dead register value stays unknown; it is not a native pointer
// obligation. Native m32 remains mandatory even when no output is observed.
func x86ResultScalarReciprocalStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86ScalarReciprocalProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawScalarReciprocalSource(ins, arch) {
			return false, true
		}
		// Project only this exact sealed source into the paired native step.
		// No caller, raw-entry, storage or later-read fact follows from it.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	source := ins.Args[0]
	computed := uint64(0xf)
	if source.Kind == OpReg {
		index, _ := amd64ParseXReg(source.Reg)
		if state.vectorBytes(index)&0xf != 0xf {
			computed = 0
		}
	} else if !x86ResultReadWithNativeContinuation(ins, source, 4, state, owned, arch, native) {
		return false, true
	}
	base, _ := amd64ParseXReg(ins.Args[form.base].Reg)
	destination, _ := amd64ParseXReg(ins.Args[form.destination].Reg)
	defined := state.vectorBytes(base)&0xfff0 | computed
	state.writeVector(destination, 16, defined, !form.spec.vector)
	return true, true // The opcode changes neither FLAGS, DF nor MXCSR.
}

func x86RawScalarReciprocalSource(ins Instr, arch string) bool {
	_, known, err := x86ScalarReciprocalProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}
