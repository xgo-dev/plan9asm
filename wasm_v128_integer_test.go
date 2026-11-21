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
	return strings.HasPrefix(op, "Extend") || strings.HasPrefix(op, "ExtaddPairwise")
}

func wasmV128IntegerWideningReference(op string, width uint, a, b [2]uint64) [2]uint64 {
	// Go integer arithmetic provides an independent lane-by-lane oracle.
	sourceWidth := width / 2
	inputMask := uint64(1)<<sourceWidth - 1
	resultMask := uint64(1)<<width - 1
	laneCount := 128 / width
	loadLane := func(vector [2]uint64, lane uint) uint64 {
		offset := lane * sourceWidth
		value := (vector[offset/64] >> (offset % 64)) & inputMask
		if strings.HasSuffix(op, "S") && value>>(sourceWidth-1) != 0 {
			value |= ^inputMask
		}
		return value
	}
	var result [2]uint64
	for lane := uint(0); lane < laneCount; lane++ {
		input := lane
		if strings.Contains(op, "High") {
			input += laneCount
		}
		var value uint64
		switch {
		case strings.HasPrefix(op, "ExtaddPairwise"):
			value = loadLane(a, lane*2) + loadLane(a, lane*2+1)
		case strings.HasPrefix(op, "Extmul"):
			value = loadLane(a, input) * loadLane(b, input)
		default:
			value = loadLane(a, input)
		}
		offset := lane * width
		result[offset/64] |= (value & resultMask) << (offset % 64)
	}
	return result
}

func wasmV128IntegerShift(op string) bool {
	return op == "Shl" || op == "ShrS" || op == "ShrU"
}

func wasmV128IntegerNarrowingBounds(op string, width uint) (int64, int64) {
	if strings.HasSuffix(op, "S") {
		limit := int64(1) << (width - 1)
		return -limit, limit - 1
	}
	return 0, int64(1)<<width - 1
}

func wasmV128IntegerNarrowingPatterns(op string, width uint) [][3][2]uint64 {
	low, high := wasmV128IntegerNarrowingBounds(op, width)
	sourceLimit := int64(1) << (width*2 - 1)
	values := [...]int64{-sourceLimit, low - 1, low, low + 1, -1, 0, 1, high - 1, high, high + 1, sourceLimit - 1}
	patterns := make([][3][2]uint64, len(values))
	mask := uint64(1)<<(width*2) - 1
	for seed := range patterns {
		for lane := uint(0); lane < 64/width; lane++ {
			offset := lane * width * 2
			first := uint64(values[(seed+int(lane)*3)%len(values)]) & mask
			second := uint64(values[(seed+int(lane)*7+1)%len(values)]) & mask
			patterns[seed][0][offset/64] |= first << (offset % 64)
			patterns[seed][1][offset/64] |= second << (offset % 64)
		}
	}
	return patterns
}

func wasmV128IntegerNarrowingReference(op string, width uint, a, b [2]uint64) [2]uint64 {
	low, high := wasmV128IntegerNarrowingBounds(op, width)
	mask := uint64(1)<<width - 1
	var result [2]uint64
	for half, input := range [2][2]uint64{a, b} {
		for lane := uint(0); lane < 64/width; lane++ {
			offset := lane * width * 2
			value := input[offset/64] >> (offset % 64)
			// Both signed and unsigned output formats take signed input.
			shift := 64 - width*2
			signed := int64(value<<shift) >> shift
			switch {
			case signed < low:
				signed = low
			case signed > high:
				signed = high
			}
			result[half] |= (uint64(signed) & mask) << (lane * width)
		}
	}
	return result
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
