package plan9asm

import (
	"encoding/binary"
	"math"

	"golang.org/x/arch/arm64/arm64asm"
)

type arm64PoolMaskedDefinition struct {
	destination, source int
	mask                uint64
}

// Normalize immediate and shifted-register AND/BIC, including flag-setting
// forms, only after typed decoding. Both residue and difference proofs consume
// this same definition; an unknown register mask is not a constant.
func (flow *arm64RawPoolValues) maskedConstantDefinition(at int, word uint32) (arm64PoolMaskedDefinition, bool) {
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	if err != nil || word>>31 == 0 || word&31 == 31 ||
		(ins.Op != arm64asm.AND && ins.Op != arm64asm.ANDS && ins.Op != arm64asm.BIC && ins.Op != arm64asm.BICS) {
		return arm64PoolMaskedDefinition{}, false
	}
	var mask uint64
	source := int(word >> 5 & 31)
	switch {
	case word&0x1f800000 == 0x12000000:
		switch immediate := ins.Args[2].(type) {
		case arm64asm.Imm:
			mask = uint64(immediate.Imm)
		case arm64asm.Imm64:
			mask = immediate.Imm
		default:
			return arm64PoolMaskedDefinition{}, false
		}
	case word&0x1f000000 == 0x0a000000:
		value, known := flow.independentMaskConstant(at, int(word>>16&31))
		if !known {
			// Unshifted AND is commutative; BIC and a shifted variable source
			// cannot be exchanged with the constant mask in this grammar.
			if (ins.Op != arm64asm.AND && ins.Op != arm64asm.ANDS) || word>>10&63 != 0 {
				return arm64PoolMaskedDefinition{}, false
			}
			value, known = flow.independentMaskConstant(at, source)
			if !known {
				return arm64PoolMaskedDefinition{}, false
			}
			source = int(word >> 16 & 31)
		}
		operand := arm64PoolLogicalOperand{must: value, may: value}.shifted(word>>22&3, word>>10&63)
		mask = operand.must
	default:
		return arm64PoolMaskedDefinition{}, false
	}
	if ins.Op == arm64asm.BIC || ins.Op == arm64asm.BICS {
		mask = ^mask
	}
	return arm64PoolMaskedDefinition{int(word & 31), source, mask}, true
}

func (flow *arm64RawPoolValues) independentMaskConstant(at, register int) (uint64, bool) {
	// Preserve the enclosing budget and never interpret a pool-relative
	// offset as the mask's numeric bit pattern.
	numeric := *flow.numericValues()
	numeric.clearValueCaches()
	value := numeric.invariantInterval(at, arm64PoolRegisterExpression(register))
	flow.affineWork += numeric.affineWork
	return value.low, value.low == value.high
}

// n-(n&mask) equals n&^mask without borrow. Retain that relation even when the
// removed bits vary. The source must survive the write; an in-place mask's old
// source cannot be confused with its new destination.
func (flow *arm64RawPoolValues) maskedDifferenceBound(at int, word uint32, query arm64PoolAffine, constraints []arm64PoolConstraint) (arm64PoolInterval, bool) {
	definition, ok := flow.maskedConstantDefinition(at, word)
	if !ok || definition.source == definition.destination {
		return arm64PoolInterval{}, false
	}
	scale := -query.coefficient[definition.destination]
	if scale == 0 {
		return arm64PoolInterval{}, false
	}
	relation := arm64PoolRegisterExpression(definition.source)
	relation.add(arm64PoolRegisterExpression(definition.destination), -1)
	remainder := query
	if !remainder.add(relation, -scale) {
		return arm64PoolInterval{}, false
	}
	// The destination is now eliminated. Every remaining register has the
	// same value before and after this instruction, so entry definitions are
	// valid for the independent residual, including an aliased source.
	residual := flow.invariantInterval(at, remainder)
	if residual == arm64PoolUnknownInterval {
		residual = flow.affineInterval(at, remainder)
	}
	if residual == arm64PoolUnknownInterval {
		return arm64PoolInterval{}, false
	}
	input := flow.integerInterval(at, arm64asm.X0+arm64asm.Reg(definition.source))
	span := arm64PoolMaskInterval(input, ^definition.mask)
	// Apply matching guards before a negative displacement can wrap the
	// unsigned image, e.g. n-(n&mask) != 0 followed by subtracting one.
	constraint := arm64PoolTightenConstraint(arm64PoolConstraint{expression: relation, interval: span}, constraints)
	if constraint.interval.low > constraint.interval.high {
		return constraint.interval, true
	}
	result := arm64PoolIntervalImage(constraint.interval, scale, residual.low)
	width := residual.high - residual.low
	if result.high > math.MaxUint64-width || flow.affineWork >= 16384 {
		return arm64PoolInterval{}, false
	}
	result.high += width
	return result, true
}
