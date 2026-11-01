package plan9asm

// ADDVL/ADDPL preserve one relocated address. Their signed six-bit immediate
// scales the architectural VL (16..256 bytes) or PL (2..32 bytes), never merely
// the host's current value. RDVL produces a number, not an address alias.
func arm64RawPoolScalableAlias(form arm64RawSVEAddress, offset arm64RawPoolRange, bounds *arm64RawPoolBounds) (arm64RawPoolRange, bool) {
	if form.op == "RDVL" || form.destination == 31 || bounds == nil {
		return arm64RawPoolRange{}, false
	}
	if bounds.symbolic {
		// Numeric offsets are recovered from reaching definitions at every
		// dereference. Only a fixed architectural partition can model them.
		return arm64RawPoolRange{}, bounds.values.vectorBytes != 0
	}
	unit := int64(16)
	if form.op == "ADDPL" {
		unit = 2
	}
	low := int64(form.immediate) * unit
	high := low * 16
	if low > high {
		low, high = high, low
	}
	if offset.low < 0 || offset.high > bounds.size ||
		low < -offset.low || high > bounds.size-offset.high {
		return arm64RawPoolRange{}, false
	}
	return arm64RawPoolRange{offset.low + low, offset.high + high}, true
}
