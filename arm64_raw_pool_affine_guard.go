package plan9asm

import "math"

func (state *arm64PoolAffineState) addConstraint(constraint arm64PoolConstraint) bool {
	for n := 0; n < state.count; n++ {
		previous := &state.constraints[n]
		if previous.expression != constraint.expression || previous.mask != constraint.mask || previous.after != constraint.after {
			continue
		}
		if constraint.interval.low > previous.interval.low {
			previous.interval.low = constraint.interval.low
		}
		if constraint.interval.high < previous.interval.high {
			previous.interval.high = constraint.interval.high
		}
		return true
	}
	if state.count == len(state.constraints) {
		return false
	}
	state.constraints[state.count] = constraint
	state.count++
	return true
}

// Called only after infeasible constants have been rejected. Satisfied constant
// guards are tautologies, and substitution may make different guards identical.
// Neither should consume the small budget for still-symbolic path predicates.
func (state *arm64PoolAffineState) compactConstraints() {
	count := state.count
	state.count = 0
	for _, constraint := range state.constraints[:count] {
		if constraint.after != 0 || !constraint.expression.isConstant() {
			state.addConstraint(constraint)
		}
	}
	for n := state.count; n < count; n++ {
		state.constraints[n] = arm64PoolConstraint{}
	}
}

func (flow *arm64RawPoolValues) affineEdgeConstraint(edge arm64RawPoolEdge) (arm64PoolConstraint, bool) {
	var constraint arm64PoolConstraint
	word := flow.words[edge.from]
	if word&0xfe000000 == 0xb4000000 { // CBZ/CBNZ X: W does not bound the high bits.
		target := edge.from + int(int32(word<<8)>>13)
		if target == edge.from+1 || edge.to != target && edge.to != edge.from+1 {
			return constraint, false
		}
		constraint.expression = arm64PoolRegisterExpression(int(word & 31))
		if (edge.to == target) == (word&(1<<24) != 0) {
			constraint.interval = arm64PoolInterval{1, math.MaxUint64}
		}
		return constraint, true
	}
	if word&0x7e000000 == 0x36000000 { // TBZ/TBNZ, including W views of low bits.
		target := edge.from + int(int32(word<<13)>>18)
		if target == edge.from+1 || edge.to != target && edge.to != edge.from+1 {
			return constraint, false
		}
		bit := word>>19&31 | word>>31<<5
		constraint.expression = arm64PoolRegisterExpression(int(word & 31))
		constraint.mask = uint64(1) << bit
		if (edge.to == target) == (word&(1<<24) != 0) {
			constraint.interval = arm64PoolInterval{constraint.mask, constraint.mask}
		}
		return constraint, true
	}
	if word&0xff000010 != 0x54000000 {
		return constraint, false
	}
	target := edge.from + int(int32(word<<8)>>13)
	if target == edge.from+1 || edge.to != target && edge.to != edge.from+1 {
		return constraint, false
	}
	compare, clobbered, after, ok := flow.affineFlagSourceBefore(edge.from)
	if !ok {
		return constraint, false
	}
	condition := word & 15
	if edge.to != target {
		condition ^= 1
	}
	// Z describes the modular arithmetic result, including register CMP/CMN
	// and a retained ADDS/SUBS result. A retained result is a post-instruction
	// register; CMP/CMN leave their input registers unchanged.
	if condition <= 1 {
		if compare&31 != 31 {
			constraint.expression = arm64PoolRegisterExpression(int(compare & 31))
		} else {
			_, expression, valid := arm64PoolAffineDefinition(compare &^ ((1 << 29) | 31))
			if !valid {
				return constraint, false
			}
			constraint.expression = expression
		}
		if constraint.expression.registerMask()&clobbered != 0 {
			constraint.after = after
		}
		if condition == 1 {
			constraint.interval = arm64PoolInterval{1, math.MaxUint64}
		}
		return constraint, true
	}
	// CMP/CMN immediate, 64-bit only. SP and W comparisons do not establish
	// this expression domain's 64-bit GP constraints.
	if compare&0xbf80001f != 0xb100001f || compare>>5&31 == 31 {
		return constraint, false
	}
	constraint.expression = arm64PoolRegisterExpression(int(compare >> 5 & 31))
	if constraint.expression.registerMask()&clobbered != 0 {
		constraint.after = after
	}
	constraint.interval = arm64PoolUnknownInterval
	immediate := uint64(compare >> 10 & 4095)
	if compare&(1<<22) != 0 {
		immediate <<= 12
	}
	if compare&(1<<30) == 0 { // CMN: C is the carry out of unsigned addition.
		if immediate == 0 {
			return constraint, false
		}
		switch condition {
		case 2:
			constraint.interval.low = math.MaxUint64 - immediate + 1
		case 3:
			constraint.interval.high = math.MaxUint64 - immediate
		case 0:
			constraint.interval.low = -immediate
			constraint.interval.high = -immediate
		default:
			return constraint, false
		}
		return constraint, true
	}
	switch condition {
	case 0:
		constraint.interval = arm64PoolInterval{immediate, immediate}
	case 2:
		constraint.interval.low = immediate
	case 3:
		if immediate == 0 {
			return constraint, false
		}
		constraint.interval.high = immediate - 1
	case 8:
		constraint.interval.low = immediate + 1
	case 9:
		constraint.interval.high = immediate
	default:
		return constraint, false
	}
	return constraint, true
}

// A tested bit can exclude a path only when another reaching guard proves
// that bit's value for the entire interval. Testing a low W bit never bounds
// the untested high bits of X. Keep both facts until definitions normalize
// their expressions; this retains path information across arithmetic aliases.
func arm64PoolConstraintsFeasible(constraints []arm64PoolConstraint) bool {
	for _, test := range constraints {
		if test.mask == 0 || test.after != 0 {
			continue
		}
		input := arm64PoolUnknownInterval
		for _, constraint := range constraints {
			if value, ok := test.expression.constrainedBy(constraint); ok {
				if value.low > input.low {
					input.low = value.low
				}
				if value.high < input.high {
					input.high = value.high
				}
			}
		}
		if input.low > input.high {
			return false
		}
		masked := arm64PoolMaskInterval(input, test.mask)
		if masked.high < test.interval.low || masked.low > test.interval.high {
			return false
		}
	}
	return true
}

// Intersect guards before projecting through scaled or negative offsets.
// Separate images can each straddle the unsigned wrap point even when the
// intersection has one small, non-wrapping image, e.g. 8 <= n <= 15 and 8*n-64.
func arm64PoolTightenConstraint(target arm64PoolConstraint, constraints []arm64PoolConstraint) arm64PoolConstraint {
	if target.mask != 0 || target.after != 0 {
		return target
	}
	for _, constraint := range constraints {
		if value, ok := target.expression.constrainedBy(constraint); ok {
			if value.low > target.interval.low {
				target.interval.low = value.low
			}
			if value.high < target.interval.high {
				target.interval.high = value.high
			}
		}
	}
	return target
}
