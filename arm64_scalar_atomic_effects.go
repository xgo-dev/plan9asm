package plan9asm

import "github.com/xgo-dev/plan9asm/internal/arm64atomic"

// Atomic stores and read-modify-writes can overwrite a saved link. Resolve
// their address through the same grammar as lowering, including base 31.
func (state *arm64ControlState) transferScalarAtomicStore(ins Instr, op Op) bool {
	form, matched := arm64atomic.Lookup(string(op), ins.arm64Encoded)
	if !matched {
		return false
	}
	output, data, argc := 2, 0, 3
	switch form.Kind {
	case arm64atomic.LoadExclusive, arm64atomic.LoadOrdered:
		return false
	case arm64atomic.CompareExchange:
		output, data = 0, 2
	case arm64atomic.StoreOrdered:
		output, argc = -1, 2
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
	if form.Kind == arm64atomic.StoreExclusive {
		observed = arm64ControlExternal()
	}
	if output >= 0 {
		state.write(ins.Args[output], observed, false)
	}
	return true
}
