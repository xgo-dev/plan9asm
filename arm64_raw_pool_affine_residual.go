package plan9asm

import "math"

// q = scale*guard + remainder. The remainder can be an independent bounded
// value, notably the relocated pool origin. Prove it at this exact program
// point rather than treating an unrelated register as a constant by name.
func (flow *arm64RawPoolValues) affineConstraintBound(at int, query arm64PoolAffine, constraint arm64PoolConstraint) (arm64PoolInterval, bool) {
	if constraint.mask != 0 || constraint.after != 0 {
		return arm64PoolInterval{}, false
	}
	if bound, ok := query.constrainedBy(constraint); ok {
		return bound, true
	}
	if flow.affineDirect {
		return arm64PoolInterval{}, false
	}
	// An almost-full-width NE/range guard cannot independently bound a pool
	// footprint through an unrelated residual. Recursing on it repeatedly
	// consumes the shared budget in loops. Keep the direct fact above, and
	// defer decomposition until guard intersection narrows the interval.
	if constraint.interval.high-constraint.interval.low > math.MaxInt64 {
		return arm64PoolInterval{}, false
	}
	for index, coefficient := range constraint.expression.coefficient {
		if coefficient == 0 || query.coefficient[index] == 0 || query.coefficient[index]%coefficient != 0 {
			continue
		}
		scale := query.coefficient[index] / coefficient
		remainder := query
		if !remainder.add(constraint.expression, -scale) {
			continue
		}
		// The eliminated coefficient makes this a strictly different query.
		// Recursive proof budgets and active-query detection still apply.
		residual := flow.invariantInterval(at, remainder)
		if residual == arm64PoolUnknownInterval {
			// If only part of the guard was eliminated, recursively bounding
			// its remaining operands chases the same dependency cycle. A known
			// invariant above is fine; otherwise defer until definitions have
			// normalized all guard operands out of the remainder.
			if remainder.registerMask()&constraint.expression.registerMask() != 0 {
				continue
			}
			residual = flow.affineInterval(at, remainder)
		}
		if residual == arm64PoolUnknownInterval {
			continue
		}
		bound := arm64PoolIntervalImage(constraint.interval, scale, residual.low)
		width := residual.high - residual.low
		if bound.high > math.MaxUint64-width {
			continue
		}
		bound.high += width
		return bound, true
	}
	return arm64PoolInterval{}, false
}
