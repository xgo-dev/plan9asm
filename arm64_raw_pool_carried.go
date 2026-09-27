package plan9asm

import "math"

// The loop body is already certified straight-line and single-entry. Substitute
// its effects backwards to prove a constant per-iteration delta; an unknown
// load result, nonlinear update or changing coefficient is not such a proof.
func (flow *arm64RawPoolValues) loopExpressionDelta(head, latch int, expression arm64PoolAffine) (int64, bool) {
	next := expression
	for at := latch - 1; at >= head; at-- {
		word := flow.words[at]
		writes, known := arm64RawPoolGPWrites(word)
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
// they occupy unrelated registers: p -= 8 and remaining -= 1 preserve
// p-8*remaining. Prove that invariant from the external entries, then combine
// it with the independently established counter range. No loop is unrolled or
// assumed to run once, and entry analysis cannot recursively use this rule.
func (flow *arm64RawPoolValues) carriedLoopBound(head int, query arm64PoolAffine, counter arm64PoolConstraint) (arm64PoolInterval, bool) {
	latch, ok := flow.loopLatches[head]
	if !ok || flow.affineDirect {
		return arm64PoolInterval{}, false
	}
	step, valid := flow.loopExpressionDelta(head, latch, counter.expression)
	if !valid || step != -1 {
		return arm64PoolInterval{}, false
	}
	delta, valid := flow.loopExpressionDelta(head, latch, query)
	if !valid || delta < -(1<<30) || delta > 1<<30 {
		return arm64PoolInterval{}, false
	}
	scale := -delta
	invariant := query
	if !invariant.add(counter.expression, -scale) {
		return arm64PoolInterval{}, false
	}
	entry := flow.counterLoopEntry(head, latch)
	if entry == nil {
		return arm64PoolInterval{}, false
	}
	entry.poolOrigins = flow.poolOrigins
	// Keep the entire relation while substituting entry definitions. Bounding
	// p and remaining separately would lose their correlation before the
	// cancellation that establishes the invariant constant.
	value := entry.invariantIntervalProof(head, invariant, true)
	if value == arm64PoolUnknownInterval {
		work := entry.affineWork
		value = entry.affineInterval(head, invariant)
		entry.affineWork += work
	}
	flow.affineWork += entry.affineWork
	if value == arm64PoolUnknownInterval || flow.affineWork >= 16384 {
		return arm64PoolInterval{}, false
	}
	result := arm64PoolIntervalImage(counter.interval, scale, value.low)
	width := value.high - value.low
	if result.high > math.MaxUint64-width {
		return arm64PoolInterval{}, false
	}
	result.high += width
	return result, true
}
