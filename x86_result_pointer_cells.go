package plan9asm

func x86StackCellBit(cells *[8]uint64, depth, end int) bool {
	return cells != nil && end > 0 && end <= depth &&
		cells[(end-1)/64]&(uint64(1)<<uint((end-1)%64)) != 0
}

func x86StackMarkCellBit(cells *[8]uint64, end int) {
	cells[(end-1)/64] |= uint64(1) << uint((end-1)%64)
}

func x86StackRevokeCellBits(cells *[8]uint64, depth, begin, end, word int) bool {
	if cells == nil {
		return false
	}
	first := begin + 1
	if first < word {
		first = word
	}
	last := end + word - 1
	if last > depth {
		last = depth
	}
	for boundary := first; boundary <= last; boundary++ {
		cells[(boundary-1)/64] &^= uint64(1) << uint((boundary-1)%64)
	}
	var any uint64
	for _, bits := range cells {
		any |= bits
	}
	return any != 0
}

func x86StackCellsBounded(cells *[8]uint64, depth int, arch string) bool {
	if cells == nil {
		return true
	}
	word := int(x86ResultPointerWord(arch))
	if cells[0]&((uint64(1)<<uint(word-1))-1) != 0 {
		return false // No complete word ends before the first native word.
	}
	for index, bits := range cells {
		remaining := depth - index*64
		if remaining <= 0 && bits != 0 || remaining > 0 && remaining < 64 && bits>>uint(remaining) != 0 {
			return false
		}
	}
	return true
}

// One bit at byte-end minus one means the preceding native word was pushed
// from an already established opaque incoming pointer. It does not describe
// numerical bits, a pointee or any caller/frame/entry capability. Byte ends
// preserve mixed-width stack positions without joining two halves.
func (stack *x86ResultValueStack) pointerCell(end int) bool {
	return x86StackCellBit(&stack.pointerCells, len(stack.bytes), end)
}

func (stack *x86ResultValueStack) markPointerCell(end int) {
	x86StackMarkCellBit(&stack.pointerCells, end)
}

// A write or partial pop revokes every saved word whose byte span overlaps.
// Removed bytes cannot retain a tag which a later narrow push could resurrect.
func (stack *x86ResultValueStack) revokePointerCells(begin, end, word int) {
	x86StackRevokeCellBits(&stack.pointerCells, len(stack.bytes), begin, end, word)
	if !x86StackRevokeCellBits(stack.ownedStaticAddrCells, len(stack.bytes), begin, end, word) {
		stack.ownedStaticAddrCells = nil
	}
}

func (stack *x86ResultValueStack) pointerCellsBounded(arch string) bool {
	return x86StackCellsBounded(&stack.pointerCells, len(stack.bytes), arch) &&
		x86StackCellsBounded(stack.ownedStaticAddrCells, len(stack.bytes), arch)
}

func (stack *x86ResultValueStack) ownedStaticAddrCell(end int) bool {
	return x86StackCellBit(stack.ownedStaticAddrCells, len(stack.bytes), end)
}

func (stack *x86ResultValueStack) markOwnedStaticAddrCell(end int) {
	if stack.ownedStaticAddrCells == nil {
		stack.ownedStaticAddrCells = new([8]uint64)
	}
	x86StackMarkCellBit(stack.ownedStaticAddrCells, end)
}
