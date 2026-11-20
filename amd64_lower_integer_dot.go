package plan9asm

import "fmt"

func (c *amd64Ctx) lowerIntegerPackedDotProduct(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedDotProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	var mask string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	// E4 reads one exact volatile dword per enabled output lane; broadcast
	// reads m32 iff an output lane is enabled. VEX retains its full tuple.
	first, err := c.loadX86PackedShiftLanes(ins.Args[form.first], form.byteWidth, 32, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	lanes, inputBits := form.byteWidth/4, form.spec.inputBits
	inputLanes := form.byteWidth * 8 / inputBits
	firstBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i%d>\n", firstBits, lanes, first, inputLanes, inputBits)
	second, err := c.loadPackedCompareBytes(ins.Args[form.second], form.byteWidth)
	if err != nil {
		return true, false, err
	}
	destination := ins.Args[form.destination]
	oldBytes, err := c.loadPackedCompareBytes(destination, form.byteWidth)
	if err != nil {
		return true, false, err
	}
	other := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, inputLanes, inputBits, second)
	old := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, 32, oldBytes)
	computed := c.emitPackedDotProduct(form.spec, lanes, "%"+firstBits, other, old)
	if form.mask >= 0 {
		computed = amd64ApplyI32LaneMask(c, lanes, computed, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i8>\n", out, lanes, computed, form.byteWidth)
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}
