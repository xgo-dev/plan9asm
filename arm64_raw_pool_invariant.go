package plan9asm

import "math"

// Prove an independent residual without collecting branch predicates. In a
// loop an invariant pool origin retains its value while the counter and its
// predicates change on every iteration. Repeated predicate substitution can
// obscure that simple fact. This proof unions every path and never uses a
// guard to discard one; changing recurrences and unknown effects fail closed.
func (flow *arm64RawPoolValues) invariantInterval(at int, expression arm64PoolAffine) (answer arm64PoolInterval) {
	return flow.invariantIntervalProof(at, expression, false)
}

// Full arithmetic is reserved for a certified carried invariant's entry
// expression. Ordinary speculative residual queries keep the cheap copy-only
// walk and its cache; they must not acquire this more expensive search mode.
func (flow *arm64RawPoolValues) invariantIntervalProof(at int, expression arm64PoolAffine, arithmetic bool) (answer arm64PoolInterval) {
	flow.beginAffineProof()
	query := arm64PoolAffineQuery{at, expression}
	if !arithmetic {
		if cached, ok := flow.invariantCache[query]; ok {
			return cached
		}
		if flow.invariantCache == nil {
			flow.invariantCache = make(map[arm64PoolAffineQuery]arm64PoolInterval)
		}
		defer func() { flow.invariantCache[query] = answer }()
	}
	queue := []arm64PoolAffineQuery{{at, expression}}
	visited := make(map[arm64PoolAffineQuery]bool)
	type recurrence struct {
		at          int
		coefficient [31]int64
		relocations int64
	}
	constants := make(map[recurrence]uint64)
	result, found := arm64PoolInterval{math.MaxUint64, 0}, false
	for steps := 0; len(queue) > 0; steps++ {
		if steps >= 4096 || flow.affineWork >= 16384 {
			return arm64PoolUnknownInterval
		}
		flow.affineWork++
		state := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if visited[state] {
			continue
		}
		visited[state] = true
		key := recurrence{state.at, state.expression.coefficient, state.expression.relocations}
		if previous, ok := constants[key]; ok && previous != state.expression.constant {
			return arm64PoolUnknownInterval
		}
		constants[key] = state.expression.constant
		if state.expression.isConstant() {
			value := state.expression.constant
			if value < result.low {
				result.low = value
			}
			if value > result.high {
				result.high = value
			}
			found = true
			continue
		}
		if state.at < 0 || state.at >= len(flow.before) || len(flow.before[state.at]) == 0 {
			return arm64PoolUnknownInterval
		}
		for _, previous := range flow.before[state.at] {
			if previous < 0 || flow.opaque[previous] && !flow.opaquePreserves(previous, state.expression) {
				return arm64PoolUnknownInterval
			}
			word := flow.words[previous]
			writes, known := arm64RawPoolGPWrites(word)
			if !known {
				return arm64PoolUnknownInterval
			}
			next := arm64PoolAffineQuery{previous, state.expression}
			if affected := writes & next.expression.registerMask(); affected != 0 {
				if arithmetic {
					if savedAt, saved, ok := flow.rewindStackLoad(previous, next.expression); ok {
						queue = append(queue, arm64PoolAffineQuery{savedAt, saved})
						continue
					}
				}
				destination, value, valid := flow.affineDefinition(word)
				if !valid && word&0x7f800000 == 0x72800000 {
					if constant, known := flow.materializedConstant(previous, word); known {
						destination, value, valid = int(word&31), arm64PoolAffine{constant: constant}, true
					}
				}
				if offset, origin := flow.poolOrigins[previous]; origin && word&0x9f000000 == 0x10000000 {
					destination = int(word & 31)
					if next.expression.coefficient[destination] != 1 {
						return arm64PoolUnknownInterval
					}
					value, valid = arm64PoolAffine{constant: offset, relocations: 1}, true
				}
				// Follow constants, copies and constant displacements. A changing
				// displacement recurrence is rejected above on its second visit;
				// multi-register arithmetic belongs to the guarded solver.
				if !arithmetic && !value.isConstant() {
					mask := value.registerMask()
					copy := mask != 0 && mask&(mask-1) == 0
					for _, coefficient := range value.coefficient {
						copy = copy && (coefficient == 0 || coefficient == 1)
					}
					valid = valid && copy
				}
				if !valid || affected != 1<<uint(destination) || !next.expression.substitute(destination, value) {
					return arm64PoolUnknownInterval
				}
			}
			queue = append(queue, next)
		}
	}
	if !found {
		return arm64PoolUnknownInterval
	}
	return result
}
