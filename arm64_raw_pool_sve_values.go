package plan9asm

// A VL partition represents one architectural vector length, never the host
// setting. The caller must prove every multiple of 16 bytes through 256 and
// exclude instructions that could change the vector-length execution mode.
func (flow *arm64RawPoolValues) affineDefinition(word uint32) (int, arm64PoolAffine, bool) {
	if flow.vectorBytes == 0 {
		return arm64PoolAffineDefinition(word)
	}
	if form, ok := decodeARM64RawSVEAddress(word); ok {
		if form.destination == 31 || form.op != "RDVL" && form.source == 31 {
			return 0, arm64PoolAffine{}, false
		}
		unit := flow.vectorBytes
		if form.op == "ADDPL" {
			unit /= 8
		}
		value := arm64PoolAffine{constant: uint64(int64(form.immediate) * unit)}
		if form.op != "RDVL" {
			value.coefficient[form.source] = 1
		}
		return form.destination, value, true
	}
	if form, ok := decodeARM64RawSVECnt(word); ok && !form.vector && form.destination != 31 {
		count := arm64PoolPatternCount(flow.vectorBytes*8/int64(form.elementBits), form.pattern)
		value := arm64PoolAffine{constant: uint64(count * int64(form.multiplier))}
		if form.operation != "" {
			value.coefficient[form.destination] = 1
			if form.operation == "sub" {
				value.constant = -value.constant
			}
		}
		return form.destination, value, true
	}
	return arm64PoolAffineDefinition(word)
}

// DecodePredCount: fixed VL patterns are zero if the requested element count
// does not fit. Reserved patterns are zero, not ALL. No saturating INC/DEC or
// vector destination is admitted by the scalar affine grammar above.
func arm64PoolPatternCount(elements int64, pattern int) int64 {
	switch {
	case pattern == 0:
		count := int64(1)
		for count*2 <= elements {
			count *= 2
		}
		return count
	case pattern >= 1 && pattern <= 13:
		count := int64(pattern)
		if pattern >= 9 {
			count = 16 << uint(pattern-9)
		}
		if count <= elements {
			return count
		}
	case pattern == 29:
		return elements / 4 * 4
	case pattern == 30:
		return elements / 3 * 3
	case pattern == 31:
		return elements
	}
	return 0
}

func arm64RawPoolAddressProof(instructions []Instr, end int, size int64, clobbers uint32, values *arm64RawPoolValues, origins map[int]uint64) bool {
	// Deterministic order also prevents bounded proof caches from depending on
	// map iteration. Each ADR still carries exactly one common relocation.
	for at := range values.words {
		offset, origin := origins[at]
		if !origin {
			continue
		}
		bounds := &arm64RawPoolBounds{offset: int64(offset), size: size, values: values, origins: origins}
		if arm64RawAddressOnlyLoadedWithinPool(instructions, at, end, clobbers, bounds) {
			continue
		}
		if !arm64RawAddressOnlyLoadedWithinPool(instructions, at, end, clobbers, bounds.withSymbolicOrigin(at)) {
			return false
		}
	}
	return true
}

func arm64RawPoolAllVectorLengths(instructions []Instr, start, end int, size int64, clobbers uint32, reachable map[int]bool, origins map[int]uint64) bool {
	usesLength := false
	for at := range reachable {
		word := uint32(instructions[at].Args[0].Imm)
		if word&0xfffffc1f == 0xd65f0000 {
			continue
		}
		if _, known := arm64RawPoolGPWrites(word); !known {
			return false // Calls, mode changes and unknown effects cannot fix VL.
		}
		if _, address := decodeARM64RawSVEAddress(word); address {
			usesLength = true
		}
		if form, count := decodeARM64RawSVECnt(word); count && !form.vector {
			usesLength = true
		}
		if _, memory := decodeARM64RawSVELoadStore(word); memory {
			usesLength = true
		}
	}
	if !usesLength {
		return false
	}
	for vectorBytes := int64(16); vectorBytes <= 256; vectorBytes += 16 {
		// Rebuild all CFG/loop facts, not just numeric caches: a counted loop
		// or an impossible edge may differ between vector lengths.
		values := newARM64RawPoolValuesForVL(instructions, start, end, reachable, vectorBytes)
		if !arm64RawPoolAddressProof(instructions, end, size, clobbers, values, origins) {
			return false
		}
	}
	return true
}
