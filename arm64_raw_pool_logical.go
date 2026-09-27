package plan9asm

import (
	"encoding/binary"
	"math/bits"

	"golang.org/x/arch/arm64/arm64asm"
)

// Logical operations already have lowering for the complete Go grammar. This
// proof layer recognizes when OR/XOR also preserve an affine relationship:
// operands with disjoint possible one-bits cannot carry, so OR/XOR equal ADD.
// Other cases retain conservative bit bounds, never an invented ADD identity.
type arm64PoolLogicalOperand struct {
	must, may uint64
	value     arm64PoolAffine
	affine    bool
}

func arm64PoolIntervalBits(interval arm64PoolInterval) (must, may uint64) {
	varying := uint64(1)<<uint(bits.Len64(interval.low^interval.high)) - 1
	return interval.low &^ varying, interval.high | varying
}

// A pool-relative offset is not the numeric address's bit pattern. Logical
// proofs must use ordinary integer definitions even inside a relocation proof.
func (flow *arm64RawPoolValues) integerInterval(at int, reg arm64asm.Reg) arm64PoolInterval {
	numeric := flow
	if len(flow.poolOrigins) != 0 {
		copy := *flow
		copy.poolOrigins = nil
		copy.affineCache = make(map[arm64PoolAffineQuery]arm64PoolInterval)
		copy.invariantCache = nil
		copy.affineActive = make(map[arm64PoolAffineQuery]bool)
		for query, active := range flow.affineActive {
			copy.affineActive[query] = active
		}
		numeric = &copy
	}
	expression := arm64PoolRegisterExpression(int(reg - arm64asm.X0))
	interval := numeric.invariantInterval(at, expression)
	if interval == arm64PoolUnknownInterval {
		interval = numeric.affineInterval(at, expression)
	}
	flow.affineWork = numeric.affineWork
	if upper := flow.upper(at, reg); upper < interval.high {
		interval.high = upper
	}
	if interval.low > interval.high {
		return arm64PoolUnknownInterval
	}
	return interval
}

func (flow *arm64RawPoolValues) logicalRegister(at, index int) arm64PoolLogicalOperand {
	interval := flow.integerInterval(at, arm64asm.X0+arm64asm.Reg(index))
	must, may := arm64PoolIntervalBits(interval)
	value := arm64PoolRegisterExpression(index)
	if interval.low == interval.high {
		value = arm64PoolAffine{constant: interval.low}
	}
	return arm64PoolLogicalOperand{must: must, may: may, value: value, affine: true}
}

func (operand arm64PoolLogicalOperand) shifted(kind, amount uint32) arm64PoolLogicalOperand {
	shift := func(value uint64) uint64 {
		switch kind {
		case 0:
			return value << amount
		case 1:
			return value >> amount
		case 2:
			return uint64(int64(value) >> amount)
		default:
			return bits.RotateLeft64(value, -int(amount))
		}
	}
	operand.must, operand.may = shift(operand.must), shift(operand.may)
	if operand.must == operand.may {
		operand.value = arm64PoolAffine{constant: operand.must}
		operand.affine = true
	} else if amount != 0 {
		value := arm64PoolAffine{}
		if kind == 0 && amount <= 30 && value.add(operand.value, int64(1)<<amount) {
			operand.value = value
		} else {
			operand.affine = false
		}
	}
	return operand
}

func (flow *arm64RawPoolValues) affineLogicalDefinition(at int, word uint32) (arm64PoolAffine, arm64PoolInterval, bool, bool) {
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	if err != nil || word>>31 == 0 || word&31 == 31 ||
		(ins.Op != arm64asm.ORR && ins.Op != arm64asm.EOR) {
		return arm64PoolAffine{}, arm64PoolInterval{}, false, false
	}
	// The decoder validates the complete logical-immediate/shifted-register
	// encoding. Register bit fields are used only after that typed validation.
	left := flow.logicalRegister(at, int(word>>5&31))
	var right arm64PoolLogicalOperand
	switch {
	case word&0x1f800000 == 0x12000000:
		var value uint64
		switch immediate := ins.Args[2].(type) {
		case arm64asm.Imm:
			value = uint64(immediate.Imm)
		case arm64asm.Imm64:
			value = immediate.Imm
		default:
			return arm64PoolAffine{}, arm64PoolInterval{}, false, false
		}
		right = arm64PoolLogicalOperand{
			must: value, may: value, value: arm64PoolAffine{constant: value}, affine: true,
		}
	case word&0x1f200000 == 0x0a000000:
		right = flow.logicalRegister(at, int(word>>16&31)).shifted(word>>22&3, word>>10&63)
	default:
		return arm64PoolAffine{}, arm64PoolInterval{}, false, false
	}
	interval := arm64PoolInterval{left.must | right.must, left.may | right.may}
	if ins.Op == arm64asm.EOR {
		interval.low = left.must&^right.may | right.must&^left.may
		interval.high = left.may&^right.must | right.may&^left.must
	}
	if interval.low == interval.high {
		return arm64PoolAffine{constant: interval.low}, interval, true, true
	}
	value := left.value
	affine := left.affine && right.affine && left.may&right.may == 0 && value.add(right.value, 1)
	return value, interval, affine, true
}
