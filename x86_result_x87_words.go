package plan9asm

import "strings"

// Only explicitly initialized control-word knownness is mutable state. The
// parameter offsets are immutable actual typed-layout metadata, shared by all
// CFG copies like pointerFP, not native backing or generic input-write rights.
type x86ResultX87WordState struct {
	control uint16
	layout  *x86X87WordLayout
}

type x86X87WordLayout struct {
	parameters map[int64]bool
}

func x86X87WordStateNeeded(fn Func) bool {
	for _, ins := range x86X87FlowInstructions(fn) {
		name, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
		if name == "FLDENV" {
			return true // Environment observation does not initialize the value stack.
		}
		if spec, known := x86X87ValueSpecs[Op(name)]; known &&
			(spec.kind == x86X87IntegerMove || spec.kind == x86X87Round) {
			return true // Explicit control knownness/layout, never a default CW.
		}
		if kind, known := x86X87WordSpecs[Op(name)]; known && kind != x86X87StoreStatus {
			return true // No target permission follows from this allocation predicate.
		}
	}
	return false
}

func x86ResultX87WordStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86X87WordProperties(ins, arch)
	if !known {
		return false, false
	}
	if err != nil || !x86ResultNamedPredicateInstruction(ins) || state.x87 == nil {
		return false, true
	}
	x87 := state.x87
	switch form.kind {
	case x86X87Initialize:
		if x87.word == nil {
			return false, true
		}
		if !state.shapeOnly {
			// Empty tags are not zero-valued F0..F7. Existing GP captures
			// remain physically unchanged; no GP or integer FLAGS are written.
			x87.slots, x87.depth, x87.invalid = 0, 0, false
			x87.integer = [8]uint8{}
			x87.status, x87.word.control = 0xffff, 0xffff
		}
		return true, true
	case x86X87Clear:
		if !state.shapeOnly {
			// Only B/ES/SF and the exception bits become known zero.
			// C3/TOP/C2/C1/C0 retain precisely their previous knownness.
			x87.status = x87.status&0x7f00 | 0x80ff
		}
		return true, true
	case x86X87LoadControl:
		// This is the already implemented control-word write/read role, not
		// an environment restore, stack/value producer or native memory read.
		// Only two actual mapped FP/AUTO bytes may supply it; neither static
		// bytes nor an incoming pointer acquire a new control-load permission.
		mappedSource := form.operand.Kind == OpFP || form.operand.Kind == OpMem && form.operand.Mem.Base == SP
		if x87.word == nil || !mappedSource ||
			!x86ResultRead(form.operand, 2, state, owned, arch) {
			return false, true
		}
		if !state.shapeOnly {
			x87.word.control = 0xffff
		}
		return true, true
	}
	bits := x87.status
	if form.kind == x86X87StoreControl {
		bits = 0
		if x87.word != nil {
			bits = x87.word.control
		}
	}
	if form.operand.Kind == OpReg {
		index, mask, valid := x86ResultGP(form.operand.Reg, 2, arch)
		if !valid {
			return false, true
		}
		state.gp[index] &^= mask
		if bits&0xff == 0xff {
			state.gp[index] |= 1
		}
		if bits&0xff00 == 0xff00 {
			state.gp[index] |= 2
		}
		state.canonicalGP[index] &^= mask // Defined bytes are not canonical values.
		state.pointerGP[index], state.callerAddressGP[index] = false, false
		state.callerAddressOrigin[index] = 0
		state.resultAddressGP[index] = x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP[index] = x86ResultSlotAddress{}
		}
		x87.gp[index] = bits
	} else {
		if !state.shapeOnly && bits != 0xffff {
			return false, true
		}
		if !x86ResultX87NaturalWordStore(form.operand, 2, state, owned, resultOffset, arch) {
			return false, true
		}
	}
	// Preserve the existing conservative undefined post-condition-code policy.
	// A second store cannot borrow stale full-status facts from its first read.
	x87.status = 0
	return true, true
}

// Reuse only the old exact natural I16 parameter shadow. A typed x87 integer
// store does not make other parameter spans, pointers or caller memory writable.
// Results and named AUTO keep the existing independently bounded byte writer.
func x86ResultX87NaturalWordStore(operand Operand, width int64, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) bool {
	if operand.Kind != OpFP || operand.FPOffset >= resultOffset {
		return x86ResultStore(operand, width, state, owned, resultOffset, arch)
	}
	offset := operand.FPOffset
	if width != 2 || state.x87 == nil || state.x87.word == nil || state.x87.word.layout == nil ||
		!state.x87.word.layout.parameters[offset] || offset < 0 ||
		offset > int64(len(owned))-2 || offset > int64(len(state.fp))-2 || !owned[offset] || !owned[offset+1] {
		return false
	}
	state.fp[offset], state.fp[offset+1] = true, true
	return true
}
