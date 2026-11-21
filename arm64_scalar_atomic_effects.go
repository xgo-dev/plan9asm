package plan9asm

// Atomic stores and read-modify-writes can overwrite a saved link. Resolve
// their address through the same grammar as lowering, including base 31.
func (state *arm64ControlState) transferScalarAtomicStore(ins Instr, op Op) bool {
	output, data, argc := 2, 0, 3
	status := false
	if form, matched := parseARM64ExclusiveOpcode(op); matched {
		if form.isLoad {
			return false
		}
		status = true
	} else if _, matched := parseARM64AtomicCASOpcode(op, ins.arm64Encoded); matched {
		output, data = 0, 2
	} else if _, load, matched := parseARM64AtomicLoadStoreOpcode(op); matched && !load {
		output, argc = -1, 2
	} else if _, matched := parseARM64AtomicRMWOpcode(op); !matched {
		return false
	}
	mem, err := arm64ScalarAtomicMemory(ins, 1, argc)
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
	if output >= 0 {
		state.write(ins.Args[output], observed, false)
	}
	return true
}
