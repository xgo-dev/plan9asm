package plan9asm

// One bit at byte-end minus one means the preceding native word was pushed
// from an already established opaque incoming pointer. It does not describe
// numerical bits, a pointee or any caller/frame/entry capability. Byte ends
// preserve mode32's genuinely mixed W/L positions without joining two halves.
func (stack *x86ResultValueStack) pointerCell(end int) bool {
	return end > 0 && end <= len(stack.bytes) &&
		stack.pointerCells[(end-1)/64]&(uint64(1)<<uint((end-1)%64)) != 0
}

func (stack *x86ResultValueStack) markPointerCell(end int) {
	stack.pointerCells[(end-1)/64] |= uint64(1) << uint((end-1)%64)
}

// A write or partial pop revokes every saved word whose byte span overlaps.
// Removed bytes cannot retain a tag which a later narrow push could resurrect.
func (stack *x86ResultValueStack) revokePointerCells(begin, end, word int) {
	first := begin + 1
	if first < word {
		first = word
	}
	last := end + word - 1
	if last > len(stack.bytes) {
		last = len(stack.bytes)
	}
	for boundary := first; boundary <= last; boundary++ {
		stack.pointerCells[(boundary-1)/64] &^= uint64(1) << uint((boundary-1)%64)
	}
}

func (stack *x86ResultValueStack) pointerCellsBounded(arch string) bool {
	word := int(x86ResultPointerWord(arch))
	if stack.pointerCells[0]&((uint64(1)<<uint(word-1))-1) != 0 {
		return false // No complete word ends before the first native word.
	}
	for index, bits := range stack.pointerCells {
		remaining := len(stack.bytes) - index*64
		if remaining <= 0 && bits != 0 || remaining > 0 && remaining < 64 && bits>>uint(remaining) != 0 {
			return false
		}
		if arch == "amd64" && bits&^uint64(0x8080808080808080) != 0 {
			return false // Existing AMD64 virtual cells each occupy eight bytes.
		}
	}
	return true
}
