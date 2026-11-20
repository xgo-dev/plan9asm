package plan9asm

import (
	"encoding/binary"
	"math"

	"golang.org/x/arch/arm64/arm64asm"
)

// A pool offset is an inclusive interval. Keep both endpoints: using only
// an upper bound would miss negative displacements after SUB or LDUR.
type arm64RawPoolRange struct {
	low, high int64
}

// arm64RawPoolAlias follows the address-preserving subset of MOV and ADD/SUB.
// Validate with the instruction decoder before consulting encoding fields.
// Flag-setting, truncating, stack-pointer and address-scaling forms cannot
// preserve the relocation contract and remain on the rejecting generic path.
func arm64RawPoolAlias(word uint32, at, address int, offset arm64RawPoolRange, bounds *arm64RawPoolBounds) (int, arm64RawPoolRange, bool) {
	// Most words are unrelated vector/memory instructions. Avoid decoding
	// them twice in the pointer walker; these masks are only a coarse filter.
	if word&0xffe0ffe0 != 0xaa0003e0 && word&0xbf800000 != 0x91000000 && word&0xbf000000 != 0x8b000000 {
		return 0, arm64RawPoolRange{}, false
	}
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	ins, err := arm64asm.Decode(code[:])
	if err != nil || word&31 == 31 {
		return 0, arm64RawPoolRange{}, false
	}
	destination := int(word & 31)
	if ins.Op == arm64asm.MOV && ins.Args[1] == arm64asm.X0+arm64asm.Reg(address) &&
		ins.Args[0] == arm64asm.X0+arm64asm.Reg(destination) && bounds != nil {
		return destination, offset, true
	}
	if (ins.Op != arm64asm.ADD && ins.Op != arm64asm.SUB) || word>>31 == 0 {
		return 0, arm64RawPoolRange{}, false
	}
	base, index := int(word>>5&31), int(word>>16&31)
	subtract := ins.Op == arm64asm.SUB
	delta := arm64RawPoolRange{}
	switch {
	case word&0x1f800000 == 0x11000000: // Immediate, optionally shifted by 12.
		if base != address {
			return 0, delta, false
		}
		delta.high = int64(word >> 10 & 4095)
		if word&(1<<22) != 0 {
			delta.high <<= 12
		}
		delta.low = delta.high
	case word&0x1f200000 == 0x0b000000: // Shifted register.
		shift, kind := word>>10&63, word>>22&3
		if base != address {
			// ADD is commutative only when the address itself is unshifted.
			if subtract || index != address || shift != 0 || kind != 0 {
				return 0, delta, false
			}
			index = base
		} else if index == address {
			return 0, delta, false
		}
		if bounds == nil {
			return 0, delta, false
		}
		upper := bounds.values.boundedUpper(at, arm64asm.X0+arm64asm.Reg(index))
		switch kind {
		case 0: // LSL: prove that no bit is lost or enters the sign bit.
			if upper > math.MaxInt64>>shift {
				return 0, delta, false
			}
			upper <<= shift
		case 1: // LSR.
			upper >>= shift
		case 2: // ASR, only with a proven nonnegative source.
			if upper > math.MaxInt64 {
				return 0, delta, false
			}
			upper >>= shift
		default:
			return 0, delta, false
		}
		if upper > math.MaxInt64 {
			return 0, delta, false
		}
		delta.high = int64(upper)
	case word&0x1f200000 == 0x0b200000: // Extended register; shift 0..4.
		if base != address || index == address || bounds == nil {
			return 0, delta, false
		}
		extension, shift := word>>13&7, word>>10&7
		bits := uint(8 << (extension & 3))
		reg := arm64asm.X0 + arm64asm.Reg(index)
		if bits < 64 {
			reg = arm64asm.W0 + arm64asm.Reg(index)
		}
		upper := bounds.values.boundedUpper(at, reg)
		if extension < 4 { // Unsigned extension masks the source.
			limit := uint64(math.MaxUint64) >> (64 - bits)
			if upper > limit {
				upper = limit
			}
		} else if upper > uint64(math.MaxInt64)>>(64-bits) {
			return 0, delta, false
		}
		if shift > 4 || upper > math.MaxInt64>>shift {
			return 0, delta, false
		}
		delta.high = int64(upper << shift)
	default:
		return 0, delta, false
	}
	if subtract {
		delta = arm64RawPoolRange{-delta.high, -delta.low}
	}
	// The ordinary walker can accept an in-place identity without a blob.
	if bounds == nil {
		return destination, offset, destination == address && delta.low == 0 && delta.high == 0
	}
	// Arithmetic stays in the blob (one-past may be dereferenced only with a
	// negative displacement). These checks also avoid signed host overflow.
	if delta.low < -offset.low || delta.high > bounds.size-offset.high {
		return 0, delta, false
	}
	return destination, arm64RawPoolRange{offset.low + delta.low, offset.high + delta.high}, true
}
