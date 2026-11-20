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
	// A register limit must be an independently proved numeric constant at
	// the comparison, not a later value or a relocated pool offset.
	register, immediate, subtract, valid := flow.compareConstant(compare, after-1)
	if !valid {
		return constraint, false
	}
	constraint.expression = arm64PoolRegisterExpression(register)
	if constraint.expression.registerMask()&clobbered != 0 {
		constraint.after = after
	}
	constraint.interval = arm64PoolUnknownInterval
	if !subtract { // CMN: C is the carry out of unsigned addition.
		if immediate == 0 {
			return constraint, false
		}
		// For a nonzero constant, carry and zero have the same unsigned
		// conditions as CMP against its modular negation.
		immediate = -immediate
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
		if immediate == math.MaxUint64 {
			return constraint, false
		}
		constraint.interval.low = immediate + 1
	case 9:
		constraint.interval.high = immediate
	default:
		return constraint, false
	}
	return constraint, true
}

// affineFlagSourceBefore already validated the CMP/CMN encoding with the
// architecture decoder. Cover its immediate, shifted-register and extended-
// register operand classes. SP and W comparisons stay outside this X domain.
func (flow *arm64RawPoolValues) compareConstant(word uint32, at int) (register int, value uint64, subtract, ok bool) {
	register, subtract = int(word>>5&31), word&(1<<30) != 0
	if register == 31 {
		return
	}
	if word&0xbf80001f == 0xb100001f {
		value = uint64(word >> 10 & 4095)
		if word&(1<<22) != 0 {
			value <<= 12
		}
		ok = true
		return
	}
	if word&0xbf00001f != 0xab00001f {
		return
	}
	numeric := flow.numericValues()
	bound := numeric.invariantInterval(at, arm64PoolRegisterExpression(int(word>>16&31)))
	flow.affineWork = numeric.affineWork
	if bound.low != bound.high {
		return
	}
	value = bound.low
	if word&(1<<21) == 0 {
		shift := word >> 10 & 63
		switch word >> 22 & 3 {
		case 0:
			value <<= shift
		case 1:
			value >>= shift
		case 2:
			value = uint64(int64(value) >> shift)
		default:
			return
		}
	} else {
		width := uint32(8) << (word >> 13 & 3)
		value <<= 64 - width
		if word&(1<<15) != 0 {
			value = uint64(int64(value) >> (64 - width))
		} else {
			value >>= 64 - width
		}
		value <<= word >> 10 & 7
	}
	ok = true
	return
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
