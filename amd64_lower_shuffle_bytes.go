package plan9asm

import "fmt"

// lowerPackedByteShuffle implements all Go 1.27 PSHUFB/VPSHUFB forms.
// VPSHUFB applies the byte shuffle independently to each 128-bit lane; EVEX
// writemasks operate at byte granularity.
func (c *amd64Ctx) lowerPackedByteShuffle(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86ByteShuffleProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy byte shuffle m128 needs original native storage, not virtual FP/SP/BP", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	byteWidth := form.byteWidth
	data, err := c.loadPackedCompareBytes(second, byteWidth)
	if err != nil {
		return true, false, err
	}
	var result string
	if form.legacy && form.memory >= 0 {
		// Keep the original opcode, including m128 alignment and dead faults.
		// The portable E4NF reader alone cannot reproduce this legacy effect.
		result, err = c.emitPackedBinaryNativeMemory(first, 8, data, "pshufb")
	} else if ins.x86RIPLiteral && len(ins.x86RIPLiteralData) == byteWidth {
		result = c.emitPackedByteShuffleLiteral(byteWidth, data, ins.x86RIPLiteralData)
	} else {
		// E4NF: all control bytes are read, even with a dead or zero-masked
		// result. Reuse the exact full-tuple reader, not the E4 lane reader.
		control, err := c.loadPackedUnpackSource(first, x86PackedUnpackForm{
			x86PackedBinaryForm: form, spec: x86PackedUnpackSpec{laneBits: 8},
		})
		if err != nil {
			return true, false, err
		}
		result = c.emitPackedByteShuffle(byteWidth, data, control)
	}
	if err != nil {
		return true, false, err
	}
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		old, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, byteWidth, 8, result, old, mask, form.zeroing)
	}
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, result)
	}
	return true, false, c.storePackedMoveOperand(destination, byteWidth, result)
}

func (c *amd64Ctx) emitPackedByteShuffleLiteral(byteWidth int, data string, control []byte) string {
	indices := make([]int, byteWidth)
	for index, selected := range control {
		if selected&0x80 != 0 {
			indices[index] = byteWidth // Select a zero from the second vector.
		} else {
			indices[index] = index/16*16 + int(selected&0x0f)
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> %s\n",
		result, byteWidth, data, byteWidth, byteWidth, llvmI32Mask(indices))
	return "%" + result
}

func (c *amd64Ctx) emitPackedByteShuffle(byteWidth int, data, control string) string {
	if byteWidth == 16 {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %s, <16 x i8> %s)\n", call, data, control)
		return "%" + call
	}

	parts := make([]string, 0, byteWidth/16)
	for lane := 0; lane < byteWidth/16; lane++ {
		dataLane := c.newTmp()
		controlLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <16 x i32> %s\n", dataLane, byteWidth, data, byteWidth, llvmI32RangeMask(lane*16, 16))
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <16 x i32> %s\n", controlLane, byteWidth, control, byteWidth, llvmI32RangeMask(lane*16, 16))
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %%%s, <16 x i8> %%%s)\n", call, dataLane, controlLane)
		parts = append(parts, "%"+call)
	}
	partWidth := 16
	for len(parts) > 1 {
		combined := make([]string, 0, len(parts)/2)
		for i := 0; i < len(parts); i += 2 {
			joined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> %s\n", joined, partWidth, parts[i], partWidth, parts[i+1], partWidth*2, llvmI32RangeMask(0, partWidth*2))
			combined = append(combined, "%"+joined)
		}
		parts = combined
		partWidth *= 2
	}
	return parts[0]
}
