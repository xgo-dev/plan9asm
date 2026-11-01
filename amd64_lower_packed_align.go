package plan9asm

import "fmt"

func (c *amd64Ctx) lowerPackedAlignFamily(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedAlignProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && form.memory >= 0 &&
		(first.Kind == OpFP || !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple)) {
		return true, false, fmt.Errorf("%w: PALIGNR m128 needs original native backing and its matching x86 target", ErrProbeNeedsContext)
	}
	high, err := c.loadPackedCompareBytes(second, form.byteWidth)
	if err != nil {
		return true, false, err
	}
	if form.legacy && form.memory >= 0 {
		// Keep the original m128 opcode even for imm>=32. An unaligned
		// volatile read cannot reproduce the legacy alignment exception.
		value, err := c.emitPackedBinaryNativeMemory(first, 8, high, fmt.Sprintf("palignr $$%d,", form.immediate))
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeLegacyPackedLogical(destination, value)
	}
	// VEX/EVEX alignment is E4NF/E4NF.nb: the entire source tuple is
	// observable, irrespective of selectors, zero masks or dead outputs.
	low, err := c.loadX86PackedShiftBytes(first, form.memoryBytesOrWidth(), true)
	if err != nil {
		return true, false, err
	}
	if form.broadcast {
		bytes, broadcast := form.spec.bits/8, c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> %s\n",
			broadcast, bytes, low, bytes, form.byteWidth, llvmRepeatI8Mask(bytes, form.byteWidth))
		low = "%" + broadcast
	}
	result := c.emitPackedAlignSelectors(form, low, high)
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareBytes(destination, form.byteWidth)
			if err != nil {
				return true, false, err
			}
		}
		lanes := form.byteWidth * 8 / form.spec.bits
		computed := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.spec.bits, result)
		prior := old
		if !form.zeroing {
			prior = c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.spec.bits, old)
		}
		masked := amd64ApplyIntegerLaneMask(c, lanes, form.spec.bits, computed, prior, mask, form.zeroing)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", bytes, lanes, form.spec.bits, masked, form.byteWidth)
		result = "%" + bytes
	}
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, result)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, result)
}

func (f x86PackedAlignForm) memoryBytesOrWidth() int {
	if f.memory >= 0 {
		return f.memoryBytes
	}
	return f.byteWidth
}

func (c *amd64Ctx) emitPackedAlignSelectors(form x86PackedAlignForm, first, second string) string {
	indices := make([]int, form.byteWidth)
	zeros := false
	for output := range indices {
		indices[output] = form.sourceByte(output)
		zeros = zeros || indices[output] < 0
	}
	width := form.byteWidth
	if zeros {
		// A second shuffle supplies constant padding without poison or one
		// extract/insert chain per byte. Both numerical consumers use exactly
		// the same selectors, including the known-zero large-count domain.
		joined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> %s\n",
			joined, width, first, width, second, width*2, llvmI32RangeMask(0, width*2))
		first, second, width = "%"+joined, "zeroinitializer", width*2
		for output := range indices {
			if indices[output] < 0 {
				indices[output] = width
			}
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> %s\n",
		result, width, first, width, second, form.byteWidth, llvmI32Mask(indices))
	return "%" + result
}
