package plan9asm

import (
	"math"
	"math/bits"
	"strings"
)

// Numeric bounds are not address provenance. A may-frame value retains that
// category even when different origins or an external predecessor erase its
// usable bounds. Only a complete overwrite removes the category.
type arm64PrivateDataValue struct {
	interval arm64PoolInterval
	frame    bool
	mixed    bool
	origin   int
	stride   uint64
}

func arm64PrivateDataNumber(interval arm64PoolInterval) arm64PrivateDataValue {
	return arm64PrivateDataValue{interval: interval}
}

var arm64PrivateDataUnknown = arm64PrivateDataNumber(arm64PoolUnknownInterval)

func arm64PrivateDataGCD(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func arm64PrivateDataUnion(a, b arm64PrivateDataValue, widen bool) arm64PrivateDataValue {
	if a == b {
		return a
	}
	if a.frame && b.frame && !a.mixed && !b.mixed && a.interval.low == a.interval.high && a.interval == b.interval {
		// Reconstructing the same fixed SP displacement on another path
		// retains that address. It does not authorize different-offset joins.
		a.origin = -2
		return a
	}
	if a.frame != b.frame || a.frame && (a.mixed || b.mixed || a.origin != b.origin) {
		return arm64PrivateDataValue{frame: true, mixed: true, interval: arm64PoolUnknownInterval}
	}
	result := a
	if b.interval.low < result.interval.low {
		result.interval.low = b.interval.low
	}
	if b.interval.high > result.interval.high {
		result.interval.high = b.interval.high
	}
	if !a.frame {
		if widen && result.interval.low < a.interval.low && result.interval.low > 64 {
			result.interval.low = uint64(1) << uint(bits.Len64(result.interval.low)-1)
		}
		if widen && result.interval.high > a.interval.high && result.interval.high > 64 {
			width := bits.Len64(result.interval.high - 1)
			if width == 64 {
				result.interval.high = math.MaxUint64
			} else {
				result.interval.high = uint64(1) << uint(width)
			}
		}
		return result
	}
	delta := a.interval.low - b.interval.low
	if a.interval.low < b.interval.low {
		delta = b.interval.low - a.interval.low
	}
	result.stride = arm64PrivateDataGCD(arm64PrivateDataGCD(a.stride, b.stride), delta)
	return result
}

func arm64PrivateDataShift(input, count arm64PoolInterval, left bool, width uint) arm64PoolInterval {
	mask := uint64(math.MaxUint64)
	if width == 32 {
		mask = math.MaxUint32
	}
	input = arm64PoolMaskInterval(input, mask)
	result := arm64PoolInterval{low: math.MaxUint64}
	// The hardware masks a variable count. At most width distinct shifts
	// suffice, including a wrapping count interval or an entirely unknown one.
	for shift := uint64(0); shift < uint64(width); shift++ {
		possible := count.high-count.low >= uint64(width)-1
		if !possible {
			for value := count.low; ; value++ {
				possible = possible || value%uint64(width) == shift
				if value == count.high {
					break
				}
			}
		}
		if !possible {
			continue
		}
		value := arm64PoolInterval{input.low >> shift, input.high >> shift}
		if left {
			if input.high > mask>>shift {
				value = arm64PoolInterval{0, mask}
			} else {
				value = arm64PoolInterval{input.low << shift, input.high << shift}
			}
		}
		if value.low < result.low {
			result.low = value.low
		}
		if value.high > result.high {
			result.high = value.high
		}
	}
	return result
}

func arm64PrivateDataNarrow(input arm64PoolInterval, width int64, signed bool) arm64PoolInterval {
	if width == 8 {
		return input
	}
	mask := uint64(1) << uint(width*8)
	input = arm64PoolMaskInterval(input, mask-1)
	if !signed || input.high < mask/2 {
		return input
	}
	if input.low < mask/2 {
		return arm64PoolUnknownInterval // The signed extension crosses zero.
	}
	return arm64PoolInterval{input.low | ^(mask - 1), input.high | ^(mask - 1)}
}

func (state *arm64PrivateDataState) value(reg Reg) arm64PrivateDataValue {
	if arm64StackReg(reg) {
		return arm64PrivateDataValue{frame: true, origin: -1}
	}
	if reg == ZR {
		return arm64PrivateDataNumber(arm64PoolInterval{})
	}
	if value, present := state.regs[reg]; present {
		return value
	}
	return arm64PrivateDataUnknown
}

func (state *arm64PrivateDataState) assign(reg Reg, value arm64PrivateDataValue) bool {
	if arm64StackReg(reg) || !isARM64GeneralOrZeroReg(reg) {
		return false
	}
	if reg != ZR {
		if state.comparison.leftReg == reg || state.comparison.rightReg == reg {
			state.comparison = arm64PrivateDataCompare{}
		}
		state.regs[reg] = value
	}
	return true
}

func (state *arm64PrivateDataState) operand(operand Operand, width uint) (arm64PrivateDataValue, bool) {
	var value arm64PrivateDataValue
	switch operand.Kind {
	case OpImm:
		if operand.ImmRaw != "" || operand.ImmIsFloat {
			return value, false
		}
		number := uint64(operand.Imm)
		value = arm64PrivateDataNumber(arm64PoolInterval{number, number})
	case OpReg:
		if !arm64StackReg(operand.Reg) && !isARM64GeneralOrZeroReg(operand.Reg) {
			return value, false
		}
		value = state.value(operand.Reg)
	case OpRegShift:
		if operand.ShiftReg != "" || operand.ShiftAmount < 0 || operand.ShiftAmount >= int64(width) ||
			!isARM64GeneralOrZeroReg(operand.Reg) || operand.ShiftOp != "<<" && operand.ShiftOp != ">>" {
			return value, false
		}
		value = state.value(operand.Reg)
		if value.frame {
			return value, false
		}
		shift := uint64(operand.ShiftAmount)
		value.interval = arm64PrivateDataShift(value.interval, arm64PoolInterval{shift, shift}, operand.ShiftOp == "<<", width)
	default:
		return value, false
	}
	if width == 32 {
		if value.frame {
			return value, false
		}
		value.interval = arm64PoolMaskInterval(value.interval, math.MaxUint32)
	}
	return value, true
}

func (state *arm64PrivateDataState) arithmetic(ins Instr, at int, frameSize int64) (handled, valid bool) {
	op := string(ins.Op)
	width := uint(64)
	base := op
	if strings.HasSuffix(base, "W") {
		width, base = 32, strings.TrimSuffix(base, "W")
	}
	switch base {
	case "ADD", "SUB", "AND", "BIC", "ORR", "EOR", "MUL", "LSL", "LSR":
	default:
		return false, false
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 || ins.Args[len(ins.Args)-1].Kind != OpReg {
		return true, false
	}
	first, ok := state.operand(ins.Args[0], width)
	if !ok {
		return true, false
	}
	second, ok := state.operand(ins.Args[1], width)
	if !ok {
		return true, false
	}
	result := arm64PrivateDataUnknown
	if first.frame || second.frame {
		if width != 64 || base != "ADD" && base != "SUB" || first.frame && second.frame || base == "SUB" && first.frame {
			return true, false
		}
		address, number := second, first.interval
		if first.frame {
			address, number = first, second.interval
		}
		if address.mixed {
			return true, false
		}
		var low, high uint64
		if base == "SUB" {
			if address.interval.low < number.high {
				return true, false
			}
			low, high = address.interval.low-number.high, address.interval.high-number.low
		} else {
			if number.high > math.MaxUint64-address.interval.high {
				return true, false
			}
			low, high = address.interval.low+number.low, address.interval.high+number.high
		}
		if high > uint64(frameSize)+8 {
			return true, false
		}
		result = address
		result.interval = arm64PoolInterval{low, high}
		result.origin = at
		if number.low != number.high {
			result.stride = 1
		}
	} else {
		left, right := second.interval, first.interval
		mask := uint64(math.MaxUint64)
		if width == 32 {
			mask = math.MaxUint32
		}
		result.interval = arm64PoolInterval{0, mask}
		switch base {
		case "ADD":
			if right.high <= mask-left.high {
				result.interval = arm64PoolInterval{left.low + right.low, left.high + right.high}
			}
		case "SUB":
			if left.low >= right.high {
				result.interval = arm64PoolInterval{left.low - right.high, left.high - right.low}
			}
		case "MUL":
			if left.low == left.high && right.low == right.high {
				product := left.low * right.low & mask
				result.interval = arm64PoolInterval{product, product}
			} else if right.high == 0 || left.high <= mask/right.high {
				result.interval = arm64PoolInterval{left.low * right.low, left.high * right.high}
			}
		case "LSL", "LSR":
			result.interval = arm64PrivateDataShift(left, right, base == "LSL", width)
		default:
			lm, lp := arm64PoolIntervalBits(left)
			rm, rp := arm64PoolIntervalBits(right)
			if base == "BIC" {
				rm, rp = ^rp&mask, ^rm&mask
			}
			switch base {
			case "AND", "BIC":
				result.interval = arm64PoolInterval{lm & rm, lp & rp}
			case "ORR":
				result.interval = arm64PoolInterval{lm | rm, lp | rp}
			case "EOR":
				result.interval = arm64PoolInterval{lm&^rp | rm&^lp, lp&^rm | rp&^lm}
			}
		}
	}
	return true, state.assign(ins.Args[len(ins.Args)-1].Reg, result)
}
