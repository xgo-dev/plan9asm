package plan9asm

import (
	"encoding/binary"
	"math/bits"

	"golang.org/x/arch/arm64/arm64asm"
)

// AND is not affine. Keep its interval even when it is not an exact value.
// Only an exact result, such as [8,15] & 24 == 8, permits constant substitution.
func (flow *arm64RawPoolValues) affineMaskInterval(at int, word uint32) (arm64PoolInterval, bool) {
	if word&0xff800000 != 0x92000000 { // AND Xd, Xn, logical immediate.
		return arm64PoolInterval{}, false
	}
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	if err != nil || ins.Op != arm64asm.AND {
		return arm64PoolInterval{}, false
	}
	source, ok := ins.Args[1].(arm64asm.Reg)
	if !ok || source < arm64asm.X0 || source > arm64asm.XZR {
		return arm64PoolInterval{}, false
	}
	var mask uint64
	switch operand := ins.Args[2].(type) {
	case arm64asm.Imm:
		mask = uint64(operand.Imm)
	case arm64asm.Imm64:
		mask = operand.Imm
	default:
		return arm64PoolInterval{}, false
	}
	if flow.maskConstants == nil {
		flow.maskConstants = make(map[int]uint64)
	}
	input := flow.integerInterval(at, source)
	if input.low > input.high {
		return arm64PoolUnknownInterval, false
	}
	result := arm64PoolMaskInterval(input, mask)
	if result.low == result.high {
		flow.maskConstants[at] = result.low
	}
	return result, true
}

func arm64PoolMaskInterval(input arm64PoolInterval, mask uint64) arm64PoolInterval {
	// Bits above the highest differing endpoint bit are constant throughout
	// an unsigned interval. Everything below is conservatively free to vary.
	varying := uint64(1)<<uint(bits.Len64(input.low^input.high)) - 1
	low := input.low &^ varying & mask
	high := low | varying&mask
	if high > input.high {
		high = input.high // AND never increases an unsigned operand.
	}
	return arm64PoolInterval{low, high}
}
