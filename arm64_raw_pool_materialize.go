package plan9asm

import (
	"math"

	"golang.org/x/arch/arm64/arm64asm"
)

// Track overwritten bit fields back to an immediate seed. This is a finite
// definition walk, not a recursive value query, so a MOVK inside a changing
// loop cannot recursively ask itself for its own input. Covering every bit
// also proves a constant without an initial MOVZ/MOVN.
func (flow *arm64RawPoolValues) materializedConstant(at int, word uint32) (uint64, bool) {
	keep, value := uint64(math.MaxUint64), uint64(0)
	for steps := 0; steps < 64; steps++ {
		ins, decoded := arm64PoolDecodeWord(word)
		if !decoded {
			return 0, false
		}
		if ins.Op != arm64asm.MOVK {
			_, initial, affine := arm64PoolAffineDefinition(word)
			if affine && initial.isConstant() && initial.relocations == 0 {
				return value | initial.constant&keep, true
			}
			return 0, false
		}
		shift := (word >> 21 & 3) * 16
		mask := uint64(0xffff) << shift
		value |= uint64(word>>5&0xffff) << shift & keep
		keep &^= mask
		if word>>31 == 0 {
			keep &= math.MaxUint32
		}
		if keep == 0 {
			return value, true
		}
		_, previous, known := flow.valueDefinition(arm64PoolValuePoint{at, int(word & 31)})
		if !known {
			return 0, false
		}
		at, word = previous, flow.words[previous]
	}
	return 0, false
}

func (flow *arm64RawPoolValues) affineMoveKeepInterval(at int, word uint32) (arm64PoolInterval, bool) {
	if word&0x7f800000 != 0x72800000 || word&31 == 31 {
		return arm64PoolInterval{}, false
	}
	ins, ok := arm64PoolDecodeWord(word)
	if !ok || ins.Op != arm64asm.MOVK {
		return arm64PoolInterval{}, false
	}
	if constant, known := flow.materializedConstant(at, word); known {
		return arm64PoolInterval{constant, constant}, true
	}
	shift := (word >> 21 & 3) * 16
	mask := ^(uint64(0xffff) << shift)
	if word>>31 == 0 {
		mask &= math.MaxUint32 // A W write also clears the entire upper X half.
	}
	input := flow.integerInterval(at, arm64asm.X0+arm64asm.Reg(word&31))
	result := arm64PoolMaskInterval(input, mask)
	immediate := uint64(word>>5&0xffff) << shift
	// Both extrema have the replaced field cleared. OR is therefore an
	// exact addition of that field, with no carry into any preserved bit.
	result.low |= immediate
	result.high |= immediate
	return result, true
}
