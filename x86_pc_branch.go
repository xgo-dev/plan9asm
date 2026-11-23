package plan9asm

func x86PCBranchOffset(target Operand) (int64, bool) {
	memory := target.Mem
	return memory.Off, target.Kind == OpMem && memory == (MemRef{Base: PC, Off: memory.Off})
}

// Go's virtual PC counts source instructions, including metadata. Bound the
// displacement before converting it to a source index.
func x86PCBranchIndex(ordinal, count int, offset int64) (int, bool) {
	if offset < -int64(ordinal) || offset >= int64(count-ordinal) {
		return 0, false
	}
	return ordinal + int(offset), true
}

func (c *amd64Ctx) pcRelativeBlock(block, index int, target Operand) (int, bool) {
	offset, valid := x86PCBranchOffset(target)
	if !valid {
		return 0, false
	}
	last := len(c.blocks) - 1
	count := c.blockBase[last] + len(c.blocks[last].instrs)
	at, inside := x86PCBranchIndex(c.blockBase[block]+index, count, offset)
	if !inside {
		return 0, false
	}
	destination, found := c.blockByIdx[at]
	return destination, found && destination >= 0 && destination < len(c.blocks)
}
