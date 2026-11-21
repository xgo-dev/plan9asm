package plan9asm

import "strings"

func wasmV128IntegerParts(name string) (uint, string) {
	for _, shape := range []struct {
		prefix string
		bits   uint
	}{{"I8x16", 8}, {"I16x8", 16}, {"I32x4", 32}, {"I64x2", 64}} {
		if op, ok := strings.CutPrefix(name, shape.prefix); ok {
			return shape.bits, op
		}
	}
	return 0, ""
}

func wasmV128IntegerUnary(op string) bool {
	switch op {
	case "Abs", "Neg", "Popcnt", "AllTrue", "Bitmask":
		return true
	}
	return false
}

func wasmV128IntegerShift(op string) bool {
	return op == "Shl" || op == "ShrS" || op == "ShrU"
}

func wasmV128IntegerReductionReference(op string, width uint, a [2]uint64) uint32 {
	var signs, nonzero uint32
	mask := uint64(1)<<width - 1
	count := 128 / width
	for lane := uint(0); lane < count; lane++ {
		bit := lane * width
		value := (a[bit/64] >> (bit % 64)) & mask
		signs |= uint32(value>>(width-1)) << lane
		if value != 0 {
			nonzero++
		}
	}
	if op == "Bitmask" {
		return signs
	}
	if nonzero == uint32(count) {
		return 1
	}
	return 0
}

func wasmV128IntegerOrdering(op string) bool {
	switch op {
	case "Eq", "Ne", "LtS", "LtU", "GtS", "GtU", "LeS", "LeU", "GeS", "GeU", "MinS", "MinU", "MaxS", "MaxU":
		return true
	}
	return false
}

func wasmV128IntegerOrderingPatterns(bits uint) [][3][2]uint64 {
	mask := uint64(1)<<bits - 1
	sign := uint64(1) << (bits - 1)
	pairs := [][2]uint64{
		{0, 0}, {sign, sign}, {sign, sign - 1}, {sign - 1, sign},
		{mask, 0}, {0, mask}, {1, 2}, {2, 1},
		{sign, 0}, {0, sign}, {mask, mask}, {1, mask},
	}
	patterns := make([][3][2]uint64, len(pairs))
	for i := range patterns {
		for lane := uint(0); lane < 128/bits; lane++ {
			data := pairs[(i+5*int(lane))%len(pairs)]
			half, shift := lane*bits/64, lane*bits%64
			patterns[i][0][half] |= data[0] << shift
			patterns[i][1][half] |= data[1] << shift
		}
	}
	return patterns
}

func wasmV128IntegerOrderingReference(op string, bits uint, a, b uint64) uint64 {
	// Flipping the sign bit maps signed lane order to unsigned order, while
	// leaving the original bits available for min/max.
	x, y := a, b
	if strings.HasSuffix(op, "S") {
		sign := uint64(1) << (bits - 1)
		x, y = a^sign, b^sign
	}
	op = strings.TrimRight(op, "SU")
	var predicate bool
	switch op {
	case "Eq":
		predicate = x == y
	case "Ne":
		predicate = x != y
	case "Lt":
		predicate = x < y
	case "Gt":
		predicate = x > y
	case "Le":
		predicate = x <= y
	case "Ge":
		predicate = x >= y
	case "Min":
		if x < y {
			return a
		}
		return b
	case "Max":
		if y < x {
			return a
		}
		return b
	default:
		panic("unknown integer ordering operation: " + op)
	}
	if predicate {
		return uint64(1)<<bits - 1
	}
	return 0
}
