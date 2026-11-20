package plan9asm

import "math"

// Rewind an unchanged query through a certified loop without replacing it by
// an interval. This retains relationships to earlier definitions, such as a
// nonzero remainder guarded using a different copy of the original length.
// Only active constraints independently preserved by the entire body survive;
// a counter predicate from one iteration must not constrain its entry value.
func (flow *arm64RawPoolValues) rewindInvariantLoop(state *arm64PoolAffineState) (int, bool) {
	latch, ok := flow.loopLatches[state.at]
	if !ok || flow.affineDirect {
		return 0, false
	}
	delta, valid := flow.loopExpressionDelta(state.at, latch, state.expression)
	if !valid || delta != 0 {
		return 0, false
	}
	count := 0
	for _, constraint := range state.constraints[:state.count] {
		if constraint.after != 0 {
			continue
		}
		change, preserved := flow.loopExpressionDelta(state.at, latch, constraint.expression)
		if !preserved || change != 0 {
			continue
		}
		state.constraints[count] = constraint
		count++
	}
	for index := count; index < state.count; index++ {
		state.constraints[index] = arm64PoolConstraint{}
	}
	state.count = count
	return latch, true
}

// The loop body is already certified straight-line and single-entry. Substitute
// its effects backwards to prove a constant per-iteration delta; an unknown
// load result, nonlinear update or changing coefficient is not such a proof.
func (flow *arm64RawPoolValues) loopExpressionDelta(head, latch int, expression arm64PoolAffine) (int64, bool) {
	next := expression
	for at := latch - 1; at >= head; at-- {
		word := flow.words[at]
		writes, known := flow.gpWrites(word)
		if !known {
			return 0, false
		}
		if affected := writes & next.registerMask(); affected != 0 {
			destination, value, valid := flow.affineDefinition(word)
			if !valid || affected != 1<<uint(destination) || !next.substitute(destination, value) {
				return 0, false
			}
		}
	}
	if next.coefficient != expression.coefficient || next.relocations != expression.relocations {
		return 0, false
	}
	return int64(next.constant - expression.constant), true
}

// A carried address and the remaining count can change together even though
// they occupy unrelated registers: p -= 64 and remaining += 8 preserve
// p+8*remaining. Prove that invariant from the external entries, then combine
// it with the independently established counter range. No loop is unrolled or
// assumed to run once, and entry analysis cannot recursively use this rule.
func (flow *arm64RawPoolValues) carriedLoopBound(head int, query arm64PoolAffine, counter arm64PoolConstraint) (arm64PoolInterval, bool) {
	latch, ok := flow.loopLatches[head]
	if !ok || flow.affineDirect {
		return arm64PoolInterval{}, false
	}
	step, valid := flow.loopExpressionDelta(head, latch, counter.expression)
	if !valid || step == 0 || step < -(1<<30) || step > 1<<30 {
		return arm64PoolInterval{}, false
	}
	delta, valid := flow.loopExpressionDelta(head, latch, query)
	if !valid || delta < -(1<<30) || delta > 1<<30 || delta%step != 0 {
		return arm64PoolInterval{}, false
	}
	scale := delta / step
	invariant := query
	if !invariant.add(counter.expression, -scale) {
		return arm64PoolInterval{}, false
	}
	entry := flow.counterLoopEntry(head, latch)
	if entry == nil {
		return arm64PoolInterval{}, false
	}
	entry.poolOrigins = flow.poolOrigins
	entry.loopLatches = nil // Entry proof must not recursively summarize another loop.
	// Keep the entire relation while substituting entry definitions. Bounding
	// p and remaining separately would lose their correlation before the
	// cancellation that establishes the invariant constant.
	nearest := counter.interval.low
	if nearest > math.MaxInt64 {
		nearest = counter.interval.high
	}
	for _, anchor := range []uint64{0, nearest} {
		// Shift the reference count, not the represented address. An invariant
		// spanning unsigned zero may become one ordinary interval when centered
		// at the counter endpoint nearest zero. No wraparound is clamped away.
		anchored := invariant
		anchored.constant += uint64(scale) * anchor
		value := entry.invariantIntervalProof(head, anchored, true)
		if value == arm64PoolUnknownInterval {
			work := entry.affineWork
			value = entry.affineInterval(head, anchored)
			entry.affineWork += work
		}
		flow.affineWork += entry.affineWork
		if flow.affineWork >= 16384 {
			return arm64PoolInterval{}, false
		}
		if value == arm64PoolUnknownInterval {
			continue
		}
		result := arm64PoolIntervalImage(counter.interval, scale, value.low-uint64(scale)*anchor)
		width := value.high - value.low
		if result == arm64PoolUnknownInterval || result.high > math.MaxUint64-width {
			continue
		}
		result.high += width
		return result, true
	}
	return arm64PoolInterval{}, false
}
