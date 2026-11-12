package plan9asm

// A set bit denotes possible dependence on unspecified source padding, not
// an uninitialized LLVM value. All F/V/Z views share one 128-bit low bank.
type arm64PaddingBits [2]uint64

func arm64PaddingMask(bits int) uint64 {
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(bits)) - 1
}

func (b arm64PaddingBits) element(bits, lane int) uint64 {
	offset := bits * lane
	return b[offset/64] >> uint(offset%64) & arm64PaddingMask(bits)
}

func (b *arm64PaddingBits) setElement(bits, lane int, value uint64) {
	offset := bits * lane
	mask := arm64PaddingMask(bits) << uint(offset%64)
	b[offset/64] = b[offset/64]&^mask | value<<uint(offset%64)&mask
}

func arm64PaddingExtend(value uint64, bits int, signed bool, destinationBits int) uint64 {
	value &= arm64PaddingMask(bits)
	if signed && value&(uint64(1)<<uint(bits-1)) != 0 {
		value |= ^arm64PaddingMask(bits)
	}
	return value & arm64PaddingMask(destinationBits)
}

func arm64PaddingShift(value uint64, bits int, shift int64, right, signed bool) uint64 {
	value &= arm64PaddingMask(bits)
	if !right {
		return value << uint(shift) & arm64PaddingMask(bits)
	}
	if shift >= int64(bits) {
		if !signed {
			return 0
		}
		shift = int64(bits - 1)
	}
	result := value >> uint(shift)
	if signed && value&(uint64(1)<<uint(bits-1)) != 0 {
		result |= arm64PaddingMask(bits) &^ arm64PaddingMask(bits-int(shift))
	}
	return result
}

func arm64PaddingVectorTransfer(form arm64VectorTransferForm, source, old arm64PaddingBits) arm64PaddingBits {
	if form.copy {
		if form.lanes == 8 {
			source[1] = 0
		}
		return source
	}
	value := source.element(form.bits, form.sourceLane)
	if form.sourceGP {
		value = source[0] & arm64PaddingMask(form.bits)
	}
	if form.destinationGP {
		return arm64PaddingBits{value, 0}
	}
	result := arm64PaddingBits{}
	if form.preserve {
		result = old
	}
	for lane := 0; lane < form.lanes; lane++ {
		result.setElement(form.bits, lane+form.destinationLane, value)
	}
	return result
}

func arm64PaddingVectorShift(op Op, form arm64VectorShiftForm, source, old arm64PaddingBits) arm64PaddingBits {
	spec, right := arm64VectorShiftRightSpecs[op]
	result := arm64PaddingBits{}
	for lane := 0; lane < form.arrangement.lanes; lane++ {
		value := source.element(form.arrangement.elementBits, lane)
		shifted := arm64PaddingShift(value, form.arrangement.elementBits, form.shift, right, spec.signed)
		// Rounding and accumulation include carry propagation. Keep a sound
		// whole-element dependency rather than pretending they are pure shifts.
		if spec.rounding && value != 0 || spec.accumulate && (value != 0 || old.element(form.arrangement.elementBits, lane) != 0) {
			shifted = arm64PaddingMask(form.arrangement.elementBits)
		}
		result.setElement(form.arrangement.elementBits, lane, shifted)
	}
	return result
}
