package plan9asm

import "math"

// An unsigned numerical envelope is independent of initialized bytes and
// storage provenance. Excluding an interior value retains its convex hull.
type x86UnsignedRange struct{ minimum, maximum uint64 }

func (value x86UnsignedRange) hull(other x86UnsignedRange) x86UnsignedRange {
	if other.minimum < value.minimum {
		value.minimum = other.minimum
	}
	if other.maximum > value.maximum {
		value.maximum = other.maximum
	}
	return value
}

func (value x86UnsignedRange) refine(op Op, taken bool, bound uint64) (x86UnsignedRange, bool) {
	less, equal, greater := true, true, true
	switch x86BranchCondition(op) {
	case "CS":
		equal, greater = false, false
	case "LS":
		greater = false
	case "HI":
		less, equal = false, false
	case "CC":
		less = false
	case "EQ":
		less, greater = false, false
	case "NE":
		equal = false
	default:
		return value, true
	}
	if !taken {
		less, equal, greater = !less, !equal, !greater
	}
	if !less && value.minimum < bound {
		value.minimum = bound
	}
	if !greater && value.maximum > bound {
		value.maximum = bound
	}
	if !equal {
		if value.minimum == bound {
			if bound == math.MaxUint64 {
				return value, false
			}
			value.minimum++
		}
		if value.maximum == bound {
			if bound == 0 {
				return value, false
			}
			value.maximum--
		}
	}
	return value, value.minimum <= value.maximum
}
