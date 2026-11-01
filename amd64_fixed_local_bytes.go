package plan9asm

// These bits describe source-byte facts, not accessible storage. The existing
// frame/operand checks still bound every read and write; padding bits stay zero.
type x86FixedLocalByteSet []uint64

func newFixedLocalByteSet(size int64) x86FixedLocalByteSet {
	return make(x86FixedLocalByteSet, (size+63)/64)
}

func (bytes x86FixedLocalByteSet) has(index int64) bool {
	return bytes[index>>6]&(uint64(1)<<uint(index&63)) != 0
}

func (bytes x86FixedLocalByteSet) set(index int64, value bool) {
	mask := uint64(1) << uint(index&63)
	if value {
		bytes[index>>6] |= mask
	} else {
		bytes[index>>6] &^= mask
	}
}

func fixedLocalByteWordMask(offset, width int64) (uint64, int64) {
	count := int64(64) - (offset & 63)
	if width < count {
		count = width
	}
	return (^uint64(0) >> uint(64-count)) << uint(offset&63), count
}

func (bytes x86FixedLocalByteSet) setRange(offset, width int64, value bool) {
	for width > 0 {
		mask, count := fixedLocalByteWordMask(offset, width)
		if value {
			bytes[offset>>6] |= mask
		} else {
			bytes[offset>>6] &^= mask
		}
		offset, width = offset+count, width-count
	}
}

func (bytes x86FixedLocalByteSet) all(offset, width int64) bool {
	for width > 0 {
		mask, count := fixedLocalByteWordMask(offset, width)
		if bytes[offset>>6]&mask != mask {
			return false
		}
		offset, width = offset+count, width-count
	}
	return true
}

func (bytes x86FixedLocalByteSet) intersect(other x86FixedLocalByteSet) bool {
	changed := false
	for index, previous := range bytes {
		current := previous & other[index]
		changed = changed || current != previous
		bytes[index] = current
	}
	return changed
}
