package plan9asm

// A scalable transfer is accepted only inside a fixed architectural VL
// partition. The caller proves all partitions. Predicate loads transfer VL/8
// bytes, whereas whole-vector loads transfer VL bytes; stores are never reads
// of a relocatable constant pool.
func (bounds *arm64RawPoolBounds) wholeScalableLoadInBounds(at int, form arm64RawSVELoadStore) bool {
	if !form.load || bounds == nil || !bounds.symbolic || bounds.values.vectorBytes == 0 || form.base == 31 {
		return false
	}
	width := bounds.values.vectorBytes
	if form.predicate {
		width /= 8
	}
	expression := arm64PoolRegisterExpression(form.base)
	expression.constant = uint64(int64(form.immediate) * width)
	value := bounds.values.invariantInterval(at, expression)
	if value == arm64PoolUnknownInterval {
		value = bounds.values.affineInterval(at, expression)
	}
	return value.low <= value.high && value.high <= uint64(bounds.size) &&
		arm64RawPoolContains(int64(value.low), width, bounds.size) &&
		arm64RawPoolContains(int64(value.high), width, bounds.size)
}
