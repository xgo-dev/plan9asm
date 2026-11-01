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
	return bounds.scalableFootprintInBounds(at, expression, width)
}

// Reuse the complete signed/unsigned scalar-base LD1 grammar, including
// widening arrangements. Gather, PN, first-fault and non-faulting operations
// have different address/state contracts and are not ordinary contiguous reads.
func arm64RawPoolContiguousLoad(word uint32) (arm64RawSVELoadRow, bool) {
	row, ok := arm64RawSVEUnsignedLoadRows[word&0xffe0e000]
	if !ok {
		row, ok = arm64RawSVELoadRows[word&0xffe0e000]
	}
	if !ok || row.address != arm64SVELoadRegister && row.address != arm64SVELoadImmediate {
		return arm64RawSVELoadRow{}, false
	}
	// In particular, Xm=31 and the high immediate bit are reserved, not
	// aliases of zero. The lowerer's decoder is the authority for these fields.
	_, valid := decodeARM64RawSVELoadAddress(word, row)
	return row, valid
}

func (bounds *arm64RawPoolBounds) contiguousScalableLoadInBounds(at int, word uint32, row arm64RawSVELoadRow) bool {
	base := int(word>>5) & 31
	if bounds == nil || !bounds.symbolic || bounds.values.vectorBytes == 0 || base == 31 {
		return false
	}
	spec := arm64SVEOrdinaryMemorySpecs[row.op]
	// Conservatively assume every predicate lane is active. Extending a
	// memory element changes the destination width, never the bytes accessed.
	width := bounds.values.vectorBytes * int64(spec.memoryBits) / int64(row.elementBits)
	expression := arm64PoolRegisterExpression(base)
	if row.address == arm64SVELoadRegister {
		index := int(word>>16) & 31
		expression.add(arm64PoolRegisterExpression(index), row.scale)
	} else {
		immediate := int64(word>>16) & 15
		if immediate >= 8 {
			immediate -= 16
		}
		expression.constant = uint64(immediate * width)
	}
	return bounds.scalableFootprintInBounds(at, expression, width)
}

func (bounds *arm64RawPoolBounds) scalableFootprintInBounds(at int, expression arm64PoolAffine, width int64) bool {
	value := bounds.values.invariantInterval(at, expression)
	if value == arm64PoolUnknownInterval {
		value = bounds.values.affineInterval(at, expression)
	}
	return value.low <= value.high && value.high <= uint64(bounds.size) &&
		arm64RawPoolContains(int64(value.low), width, bounds.size) &&
		arm64RawPoolContains(int64(value.high), width, bounds.size)
}
