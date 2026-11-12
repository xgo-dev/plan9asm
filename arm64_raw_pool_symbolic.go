package plan9asm

import "golang.org/x/arch/arm64/arm64asm"

func (bounds *arm64RawPoolBounds) withSymbolicOrigin(at int) *arm64RawPoolBounds {
	copy := *bounds
	copy.symbolic = true
	origins := bounds.origins
	if len(origins) == 0 {
		origins = map[int]uint64{at: uint64(bounds.offset)}
	}
	// Origins share one pool base but remain proof-local. Never reuse a cache
	// computed with a different pool basis or modify ordinary integer analysis.
	copy.values = &arm64RawPoolValues{
		vectorBytes: bounds.values.vectorBytes,
		words:       bounds.values.words, before: bounds.values.before,
		cache: make(map[arm64RawPoolValue]uint64), active: make(map[arm64RawPoolValue]bool),
		poolOrigins: origins,
		excluded:    bounds.values.excluded, loopBounds: bounds.values.loopBounds,
		loopLatches: bounds.values.loopLatches,
	}
	return &copy
}

func (bounds *arm64RawPoolBounds) offsetAt(at int, register arm64asm.Reg, fallback arm64RawPoolRange) (arm64RawPoolRange, bool) {
	if bounds == nil || !bounds.symbolic {
		return fallback, true
	}
	expression := arm64PoolRegisterExpression(int(register - arm64asm.X0))
	value := bounds.values.invariantInterval(at, expression)
	if value == arm64PoolUnknownInterval {
		value = bounds.values.affineInterval(at, expression)
	}
	if value.low > value.high || value.high > uint64(bounds.size) {
		return arm64RawPoolRange{}, false
	}
	return arm64RawPoolRange{int64(value.low), int64(value.high)}, true
}

func arm64RawPoolSymbolicAlias(word uint32, address int) (int, bool) {
	// Restrict this extension to MOV/ADD/SUB without flag writes. The affine
	// decoder excludes truncation and SP operands. Scaling or subtracting the
	// relocated address itself would change its relocation coefficient.
	if word&0xffe0ffe0 != 0xaa0003e0 && word&0xbf800000 != 0x91000000 && word&0xbf000000 != 0x8b000000 {
		return 0, false
	}
	destination, expression, ok := arm64PoolAffineDefinition(word)
	return destination, ok && expression.coefficient[address] == 1
}
