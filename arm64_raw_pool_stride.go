package plan9asm

import "math"

func (flow *arm64RawPoolValues) counterStrideBound(at int, expression arm64PoolAffine, initial arm64PoolInterval, delta uint64) (arm64PoolInterval, bool) {
	signed := int64(delta)
	if signed == 0 || signed < -(1<<30) || signed > 1<<30 {
		return arm64PoolInterval{}, false
	}
	step := uint64(signed)
	if signed < 0 {
		step = -step
	}
	if step&(step-1) != 0 {
		return arm64PoolInterval{}, false
	}
	if signed < 0 {
		if initial.low == 0 || initial.high > math.MaxInt64 {
			return arm64PoolInterval{}, false
		}
	} else {
		if initial.low <= math.MaxInt64 {
			return arm64PoolInterval{}, false
		}
	}
	if !flow.multipleOfPowerOfTwo(at, expression, step) || initial.low > math.MaxUint64-(step-1) {
		return arm64PoolInterval{}, false
	}
	// Refine the independently proved interval with the independently proved
	// residue. For example [-19,-1] contains only -16 and -8 divisible by eight.
	initial.low = (initial.low + step - 1) &^ (step - 1)
	initial.high &^= step - 1
	if initial.low > initial.high {
		return arm64PoolInterval{}, false
	}
	if signed < 0 {
		return arm64PoolInterval{step, initial.high}, true
	}
	return arm64PoolInterval{initial.low, -step}, true
}

// Retain only the residue through arithmetic definitions. In particular,
// -(n & 24) is divisible by eight even though its interval includes values
// between the two actual possibilities -16 and -8. No branch predicate is
// needed; every predecessor must establish residue zero independently.
func (flow *arm64RawPoolValues) multipleOfPowerOfTwo(at int, expression arm64PoolAffine, step uint64) bool {
	mask := step - 1
	normalize := func(value arm64PoolAffine) arm64PoolAffine {
		value.constant &= mask
		for register, coefficient := range value.coefficient {
			value.coefficient[register] = int64(uint64(coefficient) & mask)
		}
		return value
	}
	queue := []arm64PoolAffineQuery{{at, normalize(expression)}}
	visited := make(map[arm64PoolAffineQuery]bool)
	found := false
	for work := 0; len(queue) > 0; work++ {
		if work >= 4096 || flow.affineWork >= 16384 {
			return false
		}
		flow.affineWork++
		state := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if visited[state] {
			continue
		}
		visited[state] = true
		if state.expression.relocations != 0 {
			return false
		}
		if state.expression.isConstant() {
			if state.expression.constant != 0 {
				return false
			}
			found = true
			continue
		}
		if state.at < 0 || state.at >= len(flow.before) || len(flow.before[state.at]) == 0 {
			return false
		}
		for _, previous := range flow.before[state.at] {
			if previous < 0 || flow.opaque[previous] && !flow.opaquePreserves(previous, state.expression) {
				return false
			}
			word := flow.words[previous]
			writes, known := flow.gpWrites(word)
			if !known {
				return false
			}
			next := arm64PoolAffineQuery{previous, state.expression}
			if affected := writes & next.expression.registerMask(); affected != 0 {
				if savedAt, saved, ok := flow.rewindStackLoad(previous, next.expression); ok {
					queue = append(queue, arm64PoolAffineQuery{savedAt, normalize(saved)})
					continue
				}
				destination, value, valid := flow.affineDefinition(word)
				if !valid {
					destination, value, valid = flow.maskedResidueDefinition(previous, word, mask)
				}
				if !valid || affected != 1<<uint(destination) || !next.expression.substitute(destination, value) {
					return false
				}
				next.expression = normalize(next.expression)
			}
			queue = append(queue, next)
		}
	}
	return found
}

func (flow *arm64RawPoolValues) maskedResidueDefinition(at int, word uint32, residueMask uint64) (int, arm64PoolAffine, bool) {
	definition, ok := flow.maskedConstantDefinition(at, word)
	if !ok {
		return 0, arm64PoolAffine{}, false
	}
	switch definition.mask & residueMask {
	case 0:
		return definition.destination, arm64PoolAffine{}, true
	case residueMask:
		return definition.destination, arm64PoolRegisterExpression(definition.source), true
	default:
		return 0, arm64PoolAffine{}, false
	}
}
