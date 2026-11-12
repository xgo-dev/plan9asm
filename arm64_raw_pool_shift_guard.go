package plan9asm

import (
	"math"

	"golang.org/x/arch/arm64/arm64asm"
)

func arm64PoolShiftConstraint(word uint32, constraint arm64PoolConstraint) (arm64PoolConstraint, bool) {
	if constraint.after != 0 || constraint.mask != 0 || word>>31 == 0 || word&31 == 31 ||
		constraint.expression != arm64PoolRegisterExpression(int(word&31)) {
		return constraint, false
	}
	ins, decoded := arm64PoolDecodeWord(word)
	shift, immediate := ins.Args[2].(arm64asm.Imm)
	if !decoded || ins.Op != arm64asm.LSR || !immediate {
		return constraint, false
	}
	maximum := uint64(math.MaxUint64) >> shift.Imm
	if constraint.interval.high > maximum {
		constraint.interval.high = maximum
	}
	constraint.expression = arm64PoolRegisterExpression(int(word >> 5 & 31))
	if constraint.interval.low > constraint.interval.high {
		constraint.interval = arm64PoolInterval{1, 0}
		return constraint, true
	}
	constraint.interval.low <<= shift.Imm
	constraint.interval.high = constraint.interval.high<<shift.Imm | (uint64(1)<<shift.Imm - 1)
	return constraint, true
}
