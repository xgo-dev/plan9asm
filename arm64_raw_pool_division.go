package plan9asm

import (
	"math"
	"math/bits"

	"golang.org/x/arch/arm64/arm64asm"
)

type arm64PoolValuePoint struct {
	at, register int
}

type arm64PoolQuotient struct {
	numerator arm64PoolValuePoint
	divisor   uint64
}

// Stop at joins and actual definitions, following only unchanged registers and
// exact X copies. Equal canonical points denote the same historic value; a
// current register name alone does not establish that identity.
func (flow *arm64RawPoolValues) valueDefinition(point arm64PoolValuePoint) (arm64PoolValuePoint, int, bool) {
	visited := make(map[arm64PoolValuePoint]bool)
	for steps := 0; steps < 512; steps++ {
		if point.register == 31 {
			return arm64PoolValuePoint{-1, 31}, 0, false
		}
		if point.at < 0 || point.at >= len(flow.before) || len(flow.before[point.at]) != 1 ||
			visited[point] || flow.affineWork >= 16384 {
			break
		}
		visited[point] = true
		flow.affineWork++
		previous := flow.before[point.at][0]
		if previous < 0 || flow.opaque[previous] {
			break
		}
		word := flow.words[previous]
		writes, known := arm64RawPoolGPWrites(word)
		if !known {
			break
		}
		if writes&(1<<uint(point.register)) != 0 {
			ins, decoded := arm64PoolDecodeWord(word)
			if decoded && ins.Op == arm64asm.MOV {
				destination, x := ins.Args[0].(arm64asm.Reg)
				source, reg := ins.Args[1].(arm64asm.Reg)
				if x && destination >= arm64asm.X0 && destination <= arm64asm.XZR &&
					reg && source >= arm64asm.X0 && source <= arm64asm.XZR {
					point = arm64PoolValuePoint{previous, int(source - arm64asm.X0)}
					continue
				}
			}
			return arm64PoolValuePoint{previous + 1, point.register}, previous, true
		}
		point.at = previous
	}
	return point, 0, false
}

func (flow *arm64RawPoolValues) sameValue(left, right arm64PoolValuePoint) bool {
	left, _, _ = flow.valueDefinition(left)
	right, _, _ = flow.valueDefinition(right)
	return left == right
}

func (flow *arm64RawPoolValues) unsignedShiftSource(point arm64PoolValuePoint) (arm64PoolValuePoint, uint, bool) {
	_, at, ok := flow.valueDefinition(point)
	if !ok {
		return point, 0, false
	}
	word := flow.words[at]
	ins, decoded := arm64PoolDecodeWord(word)
	amount, immediate := ins.Args[2].(arm64asm.Imm)
	if !decoded || ins.Op != arm64asm.LSR || word>>31 == 0 || !immediate {
		return point, 0, false
	}
	return arm64PoolValuePoint{at, int(word >> 5 & 31)}, uint(amount.Imm), true
}

// If d*m = 2^k + e and n_max*e < 2^k, floor(n*m/2^k) equals
// floor(n/d) for every n in the domain: even remainder d-1 cannot round up.
// Evaluate that sufficient condition with full 128-bit products, not floats
// or sampled values. A pre-shift reduces the domain and multiplies d by 2^pre.
func arm64PoolReciprocalDivisor(multiplier uint64, pre, post uint) (uint64, bool) {
	if multiplier == 0 || pre > 63 || post > 63 || uint64(1)<<post >= multiplier {
		return 0, false
	}
	power := uint64(1) << post
	divisor, remainder := bits.Div64(power, 0, multiplier)
	if remainder != 0 {
		if divisor == math.MaxUint64 {
			return 0, false
		}
		divisor++
	}
	high, error := bits.Mul64(divisor, multiplier)
	if high != power {
		return 0, false
	}
	errorHigh, _ := bits.Mul64(math.MaxUint64>>pre, error)
	if errorHigh >= power || divisor > math.MaxUint64>>pre {
		return 0, false
	}
	return divisor << pre, true
}

func (flow *arm64RawPoolValues) exactUnsignedQuotient(point arm64PoolValuePoint) (arm64PoolQuotient, bool) {
	var post uint
	for {
		source, shift, ok := flow.unsignedShiftSource(point)
		if !ok {
			break
		}
		post += shift
		if post > 63 {
			return arm64PoolQuotient{}, false
		}
		point = source
	}
	_, at, found := flow.valueDefinition(point)
	if !found {
		return arm64PoolQuotient{}, false
	}
	word := flow.words[at]
	ins, ok := arm64PoolDecodeWord(word)
	if !ok || word>>31 == 0 {
		return arm64PoolQuotient{}, false
	}
	left, right := int(word>>5&31), int(word>>16&31)
	if ins.Op == arm64asm.UDIV && post == 0 {
		divisor := flow.integerInterval(at, arm64asm.X0+arm64asm.Reg(right))
		if divisor.low != 0 && divisor.low == divisor.high {
			return arm64PoolQuotient{arm64PoolValuePoint{at, left}, divisor.low}, true
		}
		return arm64PoolQuotient{}, false
	}
	if ins.Op != arm64asm.UMULH {
		return arm64PoolQuotient{}, false
	}
	for _, pair := range [][2]int{{left, right}, {right, left}} {
		multiplier := flow.integerInterval(at, arm64asm.X0+arm64asm.Reg(pair[1]))
		if multiplier.low != multiplier.high {
			continue
		}
		source := arm64PoolValuePoint{at, pair[0]}
		var pre uint
		for {
			previous, shift, ok := flow.unsignedShiftSource(source)
			if !ok {
				break
			}
			pre += shift
			source = previous
			if pre > 63 {
				break
			}
		}
		if divisor, valid := arm64PoolReciprocalDivisor(multiplier.low, pre, post); valid {
			return arm64PoolQuotient{source, divisor}, true
		}
	}
	return arm64PoolQuotient{}, false
}

func (flow *arm64RawPoolValues) affineDivisionInterval(at int, word uint32, constraints []arm64PoolConstraint) (arm64PoolInterval, bool) {
	ins, ok := arm64PoolDecodeWord(word)
	if !ok || word>>31 == 0 || word&31 == 31 {
		return arm64PoolInterval{}, false
	}
	if ins.Op == arm64asm.MSUB {
		left, right, numerator := int(word>>5&31), int(word>>16&31), int(word>>10&31)
		for _, pair := range [][2]int{{left, right}, {right, left}} {
			quotient, valid := flow.exactUnsignedQuotient(arm64PoolValuePoint{at, pair[0]})
			if !valid {
				continue
			}
			divisor := flow.integerInterval(at, arm64asm.X0+arm64asm.Reg(pair[1]))
			if divisor.low == quotient.divisor && divisor.high == quotient.divisor &&
				flow.sameValue(quotient.numerator, arm64PoolValuePoint{at, numerator}) {
				return arm64PoolInterval{0, quotient.divisor - 1}, true
			}
		}
		return arm64PoolInterval{}, false
	}
	if ins.Op != arm64asm.LSR && ins.Op != arm64asm.UMULH && ins.Op != arm64asm.UDIV {
		return arm64PoolInterval{}, false
	}
	quotient, valid := flow.exactUnsignedQuotient(arm64PoolValuePoint{at + 1, int(word & 31)})
	if !valid {
		return arm64PoolInterval{}, false
	}
	input := arm64PoolUnknownInterval
	for _, constraint := range constraints {
		if constraint.after != 0 || constraint.mask != 0 {
			continue
		}
		for reg := 0; reg < 31; reg++ {
			// The constraint is on the post-instruction state. If the
			// destination aliases the numerator, its guard describes the new
			// quotient, not the old numerator that the quotient proof names.
			if reg == int(word&31) || constraint.expression != arm64PoolRegisterExpression(reg) ||
				!flow.sameValue(quotient.numerator, arm64PoolValuePoint{at, reg}) {
				continue
			}
			if constraint.interval.low > input.low {
				input.low = constraint.interval.low
			}
			if constraint.interval.high < input.high {
				input.high = constraint.interval.high
			}
		}
	}
	if input == arm64PoolUnknownInterval {
		input = flow.integerInterval(quotient.numerator.at, arm64asm.X0+arm64asm.Reg(quotient.numerator.register))
	}
	if input.low > input.high {
		return arm64PoolInterval{1, 0}, true
	}
	return arm64PoolInterval{input.low / quotient.divisor, input.high / quotient.divisor}, true
}
