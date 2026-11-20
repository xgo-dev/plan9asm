package plan9asm

// Scalar atomics have a memory operand before their final GP operand. Treating
// only that final operand as a write would miss an actual saved-LR overwrite.
// Reuse the lowerer's complete opcode families; operand errors remain its
// responsibility and never acquire a narrower control-effect exception here.
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
	if len(ins.Args) != 3 || ins.Args[1].Kind != OpMem {
		return false
	}
	// CAS/exclusive may leave the original bytes untouched. Arithmetic RMW
	// results are not an affine/code pointer proof either. Preserve all prior
	// address taint, but mark both stored contents and returned old bits unknown.
	memory := ins.Args[1]
	observed := arm64ControlUnion(state.source(memory, false), arm64ControlExternal())
	value := arm64ControlUnion(observed, state.source(ins.Args[data], false))
	state.write(memory, value, false)
	if status {
		observed = arm64ControlExternal()
	}
	state.write(ins.Args[output], observed, false)
	return true
}
