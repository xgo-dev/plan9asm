package plan9asm

import (
	"encoding/binary"
	"math"

	"golang.org/x/arch/arm64/arm64asm"
)

// Affine expressions use machine-width modular arithmetic. Keep relationships
// such as (end-start)*8 until a dominating guard bounds end-start; bounding
// the operands independently would discard precisely the required information.
type arm64PoolAffine struct {
	coefficient [31]int64
	constant    uint64
	relocations int64 // Unresolved common pool base; never two relocated addresses.
}

type arm64PoolInterval struct {
	low, high uint64
}

type arm64PoolConstraint struct {
	expression arm64PoolAffine
	interval   arm64PoolInterval
	mask       uint64 // Zero denotes an ordinary unmasked interval.
	after      int    // A historical flag fact activates at this program point.
}

type arm64PoolAffineState struct {
	at          int
	expression  arm64PoolAffine
	bound       arm64PoolInterval
	constraints [8]arm64PoolConstraint
	count       int
}

type arm64PoolAffineQuery struct {
	at         int
	expression arm64PoolAffine
}

var arm64PoolUnknownInterval = arm64PoolInterval{0, math.MaxUint64}

func arm64PoolRegisterExpression(index int) arm64PoolAffine {
	var expression arm64PoolAffine
	if index < 31 {
		expression.coefficient[index] = 1
	}
	return expression
}

func (expression arm64PoolAffine) isConstant() bool {
	return expression.coefficient == [31]int64{}
}

// A complexity cap is a failed proof, never permission to accept a load. The
// bounded coefficients also keep all host-side multiplication below int64 max.
func (expression *arm64PoolAffine) add(other arm64PoolAffine, scale int64) bool {
	const limit = int64(1 << 30)
	if scale < -limit || scale > limit {
		return false
	}
	relocations := expression.relocations + other.relocations*scale
	if relocations < 0 || relocations > 1 {
		return false
	}
	for n, coefficient := range other.coefficient {
		value := expression.coefficient[n] + coefficient*scale
		if value < -limit || value > limit {
			return false
		}
		expression.coefficient[n] = value
	}
	expression.constant += other.constant * uint64(scale)
	expression.relocations = relocations
	return true
}

func (expression *arm64PoolAffine) substitute(index int, value arm64PoolAffine) bool {
	scale := expression.coefficient[index]
	expression.coefficient[index] = 0
	return expression.add(value, scale)
}

// Return the exact affine image when it is one unsigned interval. An interval
// spanning the machine wrap point cannot be represented here and stays unknown.
func arm64PoolIntervalImage(input arm64PoolInterval, scale int64, delta uint64) arm64PoolInterval {
	if scale == 0 {
		return arm64PoolInterval{delta, delta}
	}
	abs := scale
	if abs < 0 {
		abs = -abs
	}
	if input.high-input.low > math.MaxUint64/uint64(abs) {
		return arm64PoolUnknownInterval
	}
	low, high := input.low*uint64(scale)+delta, input.high*uint64(scale)+delta
	if scale < 0 {
		low, high = high, low
	}
	if low > high {
		return arm64PoolUnknownInterval
	}
	return arm64PoolInterval{low, high}
}

func (expression arm64PoolAffine) constrainedBy(constraint arm64PoolConstraint) (arm64PoolInterval, bool) {
	if constraint.mask != 0 || constraint.after != 0 {
		return arm64PoolInterval{}, false
	}
	other := constraint.expression
	var scale int64
	found := false
	for n, coefficient := range other.coefficient {
		if coefficient == 0 {
			if expression.coefficient[n] != 0 {
				return arm64PoolInterval{}, false
			}
			continue
		}
		if !found {
			if expression.coefficient[n]%coefficient != 0 {
				return arm64PoolInterval{}, false
			}
			scale, found = expression.coefficient[n]/coefficient, true
		}
		if coefficient*scale != expression.coefficient[n] {
			return arm64PoolInterval{}, false
		}
	}
	if !found {
		return arm64PoolInterval{}, false
	}
	if expression.relocations != other.relocations*scale {
		return arm64PoolInterval{}, false
	}
	delta := expression.constant - other.constant*uint64(scale)
	return arm64PoolIntervalImage(constraint.interval, scale, delta), true
}

func (flow *arm64RawPoolValues) boundedUpper(at int, reg arm64asm.Reg) uint64 {
	upper := flow.upper(at, reg)
	if flow == nil || reg < arm64asm.X0 || reg >= arm64asm.XZR || upper == 0 {
		return upper
	}
	if refined := flow.affineInterval(at, arm64PoolRegisterExpression(int(reg-arm64asm.X0))).high; refined < upper {
		return refined
	}
	return upper
}

// Walk all predecessor paths, substituting definitions into both the query and
// its branch constraints. This is intentionally not a source-pattern match:
// copies, cancellation, scaling and joins share the same expression grammar.
// A changing cycle, unknown effect or exhausted budget makes the proof fail.
func (flow *arm64RawPoolValues) affineInterval(at int, expression arm64PoolAffine) (answer arm64PoolInterval) {
	// First try definitions and directly matching guards. Speculating about an
	// independent residual at every intermediate instruction can exhaust the
	// budget before reaching a simple dominating guard. Isolate the cheap
	// proof's caches: its unknowns must not poison the richer fallback.
	if flow != nil && !flow.affineDirect && len(flow.affineActive) == 0 {
		query := arm64PoolAffineQuery{at, expression}
		if cached, ok := flow.affineCache[query]; ok && cached != arm64PoolUnknownInterval {
			return cached
		}
		direct := *flow
		direct.clearValueCaches()
		direct.affineDirect = true
		if bound := direct.affineIntervalProof(at, expression); bound != arm64PoolUnknownInterval {
			if flow.affineCache == nil {
				flow.affineCache = make(map[arm64PoolAffineQuery]arm64PoolInterval)
			}
			flow.affineCache[query] = bound
			flow.affineWork = direct.affineWork
			return bound
		}
	}
	return flow.affineIntervalProof(at, expression)
}

func (flow *arm64RawPoolValues) affineIntervalProof(at int, expression arm64PoolAffine) (answer arm64PoolInterval) {
	if flow == nil || at < 0 || at >= len(flow.before) {
		return arm64PoolUnknownInterval
	}
	flow.beginAffineProof()
	query := arm64PoolAffineQuery{at, expression}
	if cached, ok := flow.affineCache[query]; ok {
		return cached
	}
	if flow.affineActive[query] || len(flow.affineActive) >= 32 {
		return arm64PoolUnknownInterval
	}
	if flow.affineActive == nil {
		flow.affineActive = make(map[arm64PoolAffineQuery]bool)
		flow.affineCache = make(map[arm64PoolAffineQuery]arm64PoolInterval)
	}
	flow.affineActive[query] = true
	defer func() {
		delete(flow.affineActive, query)
		flow.affineCache[query] = answer
	}()
	queue := []arm64PoolAffineState{{at: at, expression: expression, bound: arm64PoolUnknownInterval}}
	visited := make(map[arm64PoolAffineState]bool)
	result, found := arm64PoolInterval{math.MaxUint64, 0}, false
	addResult := func(value arm64PoolInterval) {
		if value.low < result.low {
			result.low = value.low
		}
		if value.high > result.high {
			result.high = value.high
		}
		found = true
	}
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
		if constraint, ok := flow.loopBounds[state.at]; ok {
			value, bounded := flow.affineConstraintBound(state.at, state.expression, constraint)
			if !bounded || value == arm64PoolUnknownInterval {
				value, bounded = flow.carriedLoopBound(state.at, state.expression, constraint)
			}
			if bounded && value != arm64PoolUnknownInterval {
				addResult(value)
				continue
			}
		}
		// Substitution can expose a stable origin after cancelling a transient
		// index. Resolve that complete expression without accumulating unrelated
		// loop predicates. The invariant proof preserves relocation cardinality
		// and unions all entries, including separate ADRs of the same pool.
		mask := state.expression.registerMask()
		if !flow.affineDirect && len(flow.poolOrigins) != 0 && mask != 0 && mask&(mask-1) == 0 {
			if invariant := flow.invariantInterval(state.at, state.expression); invariant != arm64PoolUnknownInterval {
				if invariant.low < state.bound.low {
					invariant.low = state.bound.low
				}
				if invariant.high > state.bound.high {
					invariant.high = state.bound.high
				}
				if invariant.low <= invariant.high {
					addResult(invariant)
				}
				continue
			}
		}
		impossible := false
		bound := state.bound
		for n, constraint := range state.constraints[:state.count] {
			if constraint.after != 0 {
				if state.at != constraint.after {
					continue
				}
				constraint.after = 0
				state.constraints[n] = constraint
			}
			constraint = arm64PoolTightenConstraint(constraint, state.constraints[:state.count])
			if constraint.interval.low > constraint.interval.high {
				impossible = true
				continue
			}
			if constraint.expression.isConstant() {
				value := constraint.expression.constant
				if constraint.mask != 0 {
					value &= constraint.mask
				}
				impossible = impossible || value < constraint.interval.low || value > constraint.interval.high
			}
			if value, ok := flow.affineConstraintBound(state.at, state.expression, constraint); ok {
				if value.low > bound.low {
					bound.low = value.low
				}
				if value.high < bound.high {
					bound.high = value.high
				}
			}
		}
		if impossible || bound.low > bound.high || !arm64PoolConstraintsFeasible(state.constraints[:state.count]) {
			continue
		}
		state.compactConstraints()
		state.bound = bound
		if state.expression.isConstant() {
			if value := state.expression.constant; value >= bound.low && value <= bound.high {
				addResult(arm64PoolInterval{value, value})
			}
			continue
		}
		if bound.low == bound.high {
			addResult(bound)
			continue
		}
		if state.at < 0 || len(flow.before[state.at]) == 0 {
			addResult(bound)
			continue
		}
	predecessors:
		for _, previous := range flow.before[state.at] {
			if previous < 0 {
				addResult(bound)
				continue
			}
			if flow.opaque[previous] {
				addResult(bound)
				continue
			}
			next := state
			next.at = previous
			if constraint, ok := flow.affineEdgeConstraint(arm64RawPoolEdge{previous, state.at}); ok {
				if !next.addConstraint(constraint) {
					return arm64PoolUnknownInterval
				}
			}
			word := flow.words[previous]
			writes, known := arm64RawPoolGPWrites(word)
			if !known {
				addResult(bound)
				continue
			}
			if writes&next.expression.registerMask() != 0 {
				if savedAt, saved, ok := flow.rewindStackLoad(previous, next.expression); ok {
					// The proof rebases all queried values, not all predicates.
					// Forget historical path facts rather than applying them to
					// unrelated register values at the earlier save.
					queue = append(queue, arm64PoolAffineState{
						at: savedAt, expression: saved, bound: next.bound,
					})
					continue
				}
			}
			destination, value, affine := flow.affineDefinition(word)
			if offset, origin := flow.poolOrigins[previous]; origin && word&0x9f000000 == 0x10000000 {
				index := int(word & 31)
				// An offset proof may replace one occurrence of the relocation
				// origin, never a sum of two aliases. The latter changes by
				// twice the relocation distance, even when its numeric offset
				// would happen to fit in the blob. Guards must not observe it.
				coefficient := next.expression.coefficient[index]
				if coefficient != 0 && coefficient != 1 {
					return arm64PoolUnknownInterval
				}
				for _, constraint := range next.constraints[:next.count] {
					if constraint.after == 0 && constraint.expression.coefficient[index] != 0 {
						return arm64PoolUnknownInterval
					}
				}
				destination, value, affine = int(word&31), arm64PoolAffine{constant: offset, relocations: 1}, true
			}
			// An earlier index proof may already have resolved this mask. Reuse
			// that exact numeric definition for predicates too: folding the
			// query must not erase a later comparison with the same result.
			if constant, cached := flow.maskConstants[previous]; !affine && cached {
				destination, value, affine = int(word&31), arm64PoolAffine{constant: constant}, true
			}
			if !affine && writes&next.expression.registerMask() != 0 {
				// Resolve a non-affine mask only when it defines the queried
				// value. An unrelated masked predicate may be forgotten below;
				// recursively proving it must not consume the address's budget.
				interval, bounded := flow.affineMaskInterval(previous, word)
				if !bounded {
					interval, bounded = flow.affineMoveKeepInterval(previous, word)
				}
				if !bounded {
					value, interval, affine, bounded = flow.affineLogicalDefinition(previous, word)
				}
				if !bounded {
					interval, bounded = flow.affineDivisionInterval(previous, word, next.constraints[:next.count])
				}
				if bounded {
					destination = int(word & 31)
					if interval.low == interval.high {
						value, affine = arm64PoolAffine{constant: interval.low}, true
					}
					constraint := arm64PoolConstraint{
						expression: arm64PoolRegisterExpression(destination), interval: interval,
					}
					// Intersect before a negative displacement or scale can
					// wrap the interval image, e.g. (n & 7) != 0 then n-1.
					constraint = arm64PoolTightenConstraint(constraint, next.constraints[:next.count])
					if constraint.interval.low > constraint.interval.high {
						continue predecessors
					}
					if span, ok := flow.affineConstraintBound(previous, next.expression, constraint); ok {
						if span.low > next.bound.low {
							next.bound.low = span.low
						}
						if span.high < next.bound.high {
							next.bound.high = span.high
						}
					}
					if next.bound.low > next.bound.high {
						continue predecessors
					}
				}
			}
			for index := 0; index < 31; index++ {
				if writes&(1<<uint(index)) == 0 {
					continue
				}
				if affine && index == destination {
					if !next.expression.substitute(index, value) {
						return arm64PoolUnknownInterval
					}
				} else if next.expression.coefficient[index] != 0 {
					addResult(next.bound)
					continue predecessors
				}
				count := 0
				for _, constraint := range next.constraints[:next.count] {
					if constraint.after == 0 && constraint.expression.coefficient[index] != 0 {
						if !affine || index != destination {
							replaced, ok := arm64PoolShiftConstraint(word, constraint)
							if !ok {
								continue
							}
							constraint = replaced
						} else if !constraint.expression.substitute(index, value) {
							continue // Forget this fact, never the queried value.
						}
					}
					next.constraints[count] = constraint
					count++
				}
				for n := count; n < next.count; n++ {
					next.constraints[n] = arm64PoolConstraint{}
				}
				next.count = count
			}
			queue = append(queue, next)
		}
	}
	if !found {
		return arm64PoolUnknownInterval
	}
	return result
}

func arm64PoolAffineDefinition(word uint32) (int, arm64PoolAffine, bool) {
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	destination := int(word & 31)
	if err != nil {
		return 0, arm64PoolAffine{}, false
	}
	if base, delta, ok := arm64PoolLoadWriteback(ins, word); ok {
		value := arm64PoolRegisterExpression(base)
		value.constant = uint64(delta)
		return base, value, true
	}
	if destination == 31 {
		return 0, arm64PoolAffine{}, false
	}
	var value arm64PoolAffine
	if ins.Op == arm64asm.MOV {
		switch source := ins.Args[1].(type) {
		case arm64asm.Imm:
			value.constant = uint64(source.Imm)
		case arm64asm.Imm64:
			value.constant = source.Imm
		case arm64asm.Reg:
			if source < arm64asm.X0 || source > arm64asm.XZR {
				if source != arm64asm.WZR {
					return 0, value, false
				}
			} else {
				value = arm64PoolRegisterExpression(int(source - arm64asm.X0))
			}
		default:
			return 0, value, false
		}
		return destination, value, true
	}
	if word>>31 == 0 {
		return 0, value, false // A W write truncates, rather than preserving X arithmetic.
	}
	if ins.Op == arm64asm.LSL {
		shift, ok := ins.Args[2].(arm64asm.Imm)
		if source, reg := ins.Args[1].(arm64asm.Reg); ok && reg && shift.Imm <= 30 && source >= arm64asm.X0 && source <= arm64asm.XZR {
			valid := value.add(arm64PoolRegisterExpression(int(source-arm64asm.X0)), int64(1)<<shift.Imm)
			return destination, value, valid
		}
	}
	if ins.Op != arm64asm.ADD && ins.Op != arm64asm.SUB && ins.Op != arm64asm.ADDS && ins.Op != arm64asm.SUBS {
		return 0, value, false
	}
	base := int(word >> 5 & 31)
	value = arm64PoolRegisterExpression(base)
	scale := int64(1)
	if ins.Op == arm64asm.SUB || ins.Op == arm64asm.SUBS {
		scale = -1
	}
	switch {
	case word&0x1f800000 == 0x11000000 && base != 31:
		immediate := uint64(word >> 10 & 4095)
		if word&(1<<22) != 0 {
			immediate <<= 12
		}
		value.constant = immediate * uint64(scale)
	case word&0x1f200000 == 0x0b000000 && word>>22&3 == 0 && word>>10&63 <= 30:
		scale *= int64(1) << (word >> 10 & 63)
		if !value.add(arm64PoolRegisterExpression(int(word>>16&31)), scale) {
			return 0, value, false
		}
	default:
		return 0, value, false
	}
	return destination, value, true
}
