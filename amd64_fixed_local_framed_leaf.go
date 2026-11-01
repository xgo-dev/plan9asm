package plan9asm

import "fmt"

// The existing expansion gives every helper RET one original callsite resume.
// Reuse that identity; no independent call graph or stack-coordinate map exists.
func (view *x86DirectTailRoot) privateFramedCall(pc int) (int, bool) {
	if !view.privateCallTransition(pc) || view.graph == nil || view.graph.fixedLocal == nil {
		return 0, false
	}
	call := pc
	if view.instructions[pc].Op == OpRET {
		call = view.edges[pc][0] - 1
	}
	if call < 0 || call >= len(view.instructions) || view.instructions[call].Op != OpCALL || len(view.edges[call]) != 1 {
		return 0, false
	}
	target := view.edges[call][0]
	if target < 0 || target >= len(view.points) {
		return 0, false
	}
	fn := view.graph.original.Funcs[view.points[target].text]
	return call, fn.FrameSize > 0 && view.graph.fixedLocal.leaves[fn.Sym] != ""
}

// A source leaf cannot call another helper. One immutable saved value therefore
// suffices, including partially known bytes and addresses; it grants no read.
type x86FixedLocalSavedBP struct {
	call  int
	value fixedLocalScalarValue
	known uint8
}

func fixedLocalFrameTransition(view *x86DirectTailRoot, pc int, state *x86FixedLocalState) error {
	call, framed := view.privateFramedCall(pc)
	if !framed {
		return nil // An observed zero-frame leaf preserves BP and FLAGS.
	}
	var saved *x86FixedLocalSavedBP
	if view.instructions[pc].Op == OpCALL {
		if state.savedBP != nil {
			return goAMD64FrameContext("framed source leaf acquired a nested call")
		}
		saved = &x86FixedLocalSavedBP{call: call, known: state.known[BP]}
		saved.value.address, saved.value.pointer = state.pointers[BP]
		saved.value.identity, saved.value.opaque = state.opaque[BP]
		saved.value.constant, saved.value.constantKnown = state.constants[BP]
		saved.value.bounds, saved.value.bounded = state.ranges[BP]
		saved.value.booleans = state.booleans[BP]
		state.savedBP = saved
	} else {
		saved = state.savedBP
		if saved == nil || saved.call != call {
			return goAMD64FrameContext("framed leaf RET lost its matching saved BP")
		}
		state.savedBP = nil
	}
	delete(state.pointers, BP)
	delete(state.opaque, BP)
	delete(state.constants, BP)
	delete(state.ranges, BP)
	delete(state.booleans, BP)
	state.known[BP] = 0
	state.flags = 0
	state.comparison = x86FixedLocalComparison{}
	if view.instructions[pc].Op == OpRET {
		value := saved.value
		state.known[BP], state.booleans[BP] = saved.known, value.booleans
		if value.pointer {
			state.pointers[BP] = value.address
		}
		if value.opaque {
			state.opaque[BP] = value.identity
		}
		if value.constantKnown {
			state.constants[BP] = value.constant
		}
		if value.bounded {
			state.setRange(BP, value.bounds)
		}
	}
	return nil
}

func mergeFixedLocalSavedBP(previous *x86FixedLocalState, current x86FixedLocalState) (bool, error) {
	first, last := previous.savedBP, current.savedBP
	if first == last {
		return false, nil
	}
	if first == nil || last == nil || first.call != last.call {
		return false, goAMD64FrameContext("fixed local CFG crosses distinct automatic BP saves")
	}
	left, right := first.value, last.value
	if left.opaque != right.opaque {
		// Match the ordinary register join: an address on only one incoming
		// path becomes unknown, never numerical knowledge or private storage.
		left.opaque, right.opaque = false, false
		left.identity, right.identity = x86FixedLocalOrigins{}, x86FixedLocalOrigins{}
	}
	value, compatible := mergeFixedLocalScalarValues(left, right)
	if !compatible {
		return false, goAMD64FrameContext("saved BP has inconsistent private address identities")
	}
	merged := x86FixedLocalSavedBP{call: first.call, value: value, known: first.known & last.known}
	if merged == *first {
		return false, nil
	}
	previous.savedBP = &merged
	return true, nil
}

func (c *amd64Ctx) lowerPrivateFrameTransition(pc int) error {
	call, framed := c.directTail.privateFramedCall(pc)
	if !framed {
		return nil
	}
	slot := fmt.Sprintf("%%private_call_bp_%d", call)
	if c.directTail.instructions[pc].Op == OpCALL {
		value, err := c.loadReg(BP)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", value, slot)
		return nil
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", value, slot)
	return c.storeReg(BP, "%"+value)
}
