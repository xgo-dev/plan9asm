package plan9asm

// Scalar atomics have a memory operand before their final GP operand. Treating
// only that final operand as a write would miss an actual saved-LR overwrite.
// Use the lowerer's address/register grammar so the analysis also treats
// encoded base 31 as SP and cannot grant effects to a malformed instruction.
func (state *arm64ControlState) transferScalarAtomicStore(ins Instr, op Op) bool {
	output, data := 2, 0
	status := false
	if form, matched := parseARM64ExclusiveOpcode(op); matched {
		if form.isLoad {
			return false
		}
		status = true
	} else if _, matched := parseARM64AtomicCASOpcode(op); matched {
		output, data = 0, 2
	} else if _, matched := parseARM64AtomicRMWOpcode(op); !matched {
		return false
	}
	mem, err := arm64ScalarAtomicMemory(ins, 1, 3)
	if err != nil {
		return false
	}
	// CAS/exclusive may leave the original bytes untouched. Arithmetic RMW
	// results are not an affine/code pointer proof either. Preserve all prior
	// address taint, but mark both stored contents and returned old bits unknown.
	memory := Operand{Kind: OpMem, Mem: mem}
	observed := arm64ControlUnion(state.source(memory, false), arm64ControlExternal())
	value := arm64ControlUnion(observed, state.source(ins.Args[data], false))
	state.write(memory, value, false)
	if status {
		observed = arm64ControlExternal()
	}
	state.write(ins.Args[output], observed, false)
	return true
}
