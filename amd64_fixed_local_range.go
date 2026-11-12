package plan9asm

import "math"

type x86FixedLocalComparison struct {
	register Reg
	constant uint64
	literal  x86StaticSBAddress
}

func cloneFixedLocalRanges(input map[Reg]x86UnsignedRange) map[Reg]x86UnsignedRange {
	if len(input) == 0 {
		return nil
	}
	copy := make(map[Reg]x86UnsignedRange, len(input))
	for reg, value := range input {
		copy[reg] = value
	}
	return copy
}

func (state *x86FixedLocalState) setRange(reg Reg, value x86UnsignedRange) {
	if state.ranges == nil {
		state.ranges = make(map[Reg]x86UnsignedRange)
	}
	state.ranges[reg] = value
}

func (state *x86FixedLocalState) revokeRange(reg Reg) {
	delete(state.ranges, reg)
	if state.comparison.register == reg {
		state.comparison = x86FixedLocalComparison{}
	}
}

// Called around the existing typed GP transfer, never as a second executor.
// Other writes revoke bounds at the same shared register-write boundaries.
func fixedLocalRangeEffect(ins Instr, effect x86TypedByteEffect, state *x86FixedLocalState) (Reg, x86UnsignedRange, x86FixedLocalComparison) {
	// The existing effect distinguishes read-only comparisons from GP writes;
	// unrelated arithmetic never re-enters the complete comparison grammar.
	if len(effect.operands) == 2 && !effect.operands[0].write && !effect.operands[1].write {
		if form, known, err := x86ScalarCompareProperties(ins.Op, ins, "amd64"); known && err == nil && form.bits == 64 {
			first, second := form.args[0], form.args[1]
			if first.Kind == OpReg && fixedLocalNumericRead(first, 8, state) {
				if !form.test && second.Kind == OpImm {
					return "", x86UnsignedRange{}, x86FixedLocalComparison{register: first.Reg, constant: uint64(second.Imm)}
				}
				if form.test && second.Kind == OpReg && first.Reg == second.Reg {
					return "", x86UnsignedRange{}, x86FixedLocalComparison{register: first.Reg}
				}
			}
		}
	}
	stem, bits, shiftFamily := amd64ScalarShiftRotateProperties(string(ins.Op))
	if shiftFamily && bits == 64 && (stem == "SHL" || stem == "SAL") {
		if form, known, err := x86ScalarShiftProperties(ins.Op, ins, "amd64"); known && err == nil &&
			!form.double && form.count.Kind == OpImm && form.destination.Kind == OpReg {
			value, bounded := state.ranges[form.destination.Reg]
			shift := uint(form.maskedCount())
			if bounded && value.maximum <= math.MaxUint64>>shift {
				return form.destination.Reg, x86UnsignedRange{value.minimum << shift, value.maximum << shift}, x86FixedLocalComparison{}
			}
		}
	}
	return "", x86UnsignedRange{}, x86FixedLocalComparison{}
}

func fixedLocalRangeEdge(state x86FixedLocalState, op Op, taken bool) (x86FixedLocalState, bool) {
	comparison := state.comparison
	if comparison.register == "" {
		return state, true
	}
	if comparison.literal.symbol != "" {
		return fixedLocalLiteralEdge(state, op, taken)
	}
	value, bounded := state.ranges[comparison.register]
	if !bounded {
		value.maximum = math.MaxUint64
	}
	next, feasible := value.refine(op, taken, comparison.constant)
	if !feasible || next == value {
		return state, feasible
	}
	state.ranges = cloneFixedLocalRanges(state.ranges)
	state.setRange(comparison.register, next)
	return state, feasible
}

func mergeFixedLocalRanges(previous *x86FixedLocalState, current x86FixedLocalState) bool {
	changed := false
	for reg, old := range previous.ranges {
		value, found := current.ranges[reg]
		if !found {
			delete(previous.ranges, reg)
			changed = true
			continue
		}
		value = value.hull(old)
		previous.ranges[reg] = value
		changed = changed || value != old
	}
	if previous.comparison != current.comparison && previous.comparison.register != "" {
		previous.comparison = x86FixedLocalComparison{}
		changed = true
	}
	return changed
}
