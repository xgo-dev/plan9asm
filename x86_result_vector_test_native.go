package plan9asm

func x86RawVectorTestSource(ins Instr, arch string) bool {
	_, known, err := x86VectorTestProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

// Exact raw identity grants a transfer-local view, not input bytes, native
// backing, physical entry or a reusable declaration/query permission.
func x86LoweredVectorTestResultStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	_, known, err := x86VectorTestProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !x86RawVectorTestSource(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86ResultVectorTestStepWithRead(ins, state, owned, arch, true)
}
