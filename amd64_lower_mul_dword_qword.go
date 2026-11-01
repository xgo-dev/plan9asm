package plan9asm

import "fmt"

func (c *amd64Ctx) lowerDwordToQwordMultiply(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedPhysical(op, ins, x86PackedDwordProduct)
}

func (c *amd64Ctx) lowerDwordToQwordMultiplyForm(op Op, ins Instr, form x86PackedPhysicalForm) (bool, bool, error) {
	var err error
	first, second, destination := form.source, ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy dword product m128 needs original native storage, not virtual FP/SP/BP", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	if form.mmx {
		if first.Kind == OpReg && first.Reg != ins.Args[form.first].Reg {
			return true, false, fmt.Errorf("%w: Go GP-spelled dword product source names the MMX bank", ErrProbeNeedsContext)
		}
		var a string
		if first.Kind == OpReg {
			a, err = c.loadReg(first.Reg)
		} else {
			var bytes string
			bytes, err = c.loadX86PackedShiftBytes(first, 8, true)
			if err == nil {
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i8> %s to i64\n", value, bytes)
				a = "%" + value
			}
		}
		if err != nil {
			return true, false, err
		}
		b, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		a = c.extendDwordScalar(c.lowDwordFromI64(a), false)
		b = c.extendDwordScalar(c.lowDwordFromI64(b), false)
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", product, a, b)
		return true, false, c.storeReg(destination.Reg, "%"+product)
	}
	lanes := form.byteWidth / 8
	var mask, result string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	if form.legacy && form.memory >= 0 {
		b, err := c.loadPackedCompareLanes(second, 16, 64, false)
		if err != nil {
			return true, false, err
		}
		// Keep the original SSE opcode's complete m128 access and alignment
		// behavior, including when the numerical result is dead.
		result, err = c.emitPackedBinaryNativeMemory(first, 64, b, form.spec.nativeOpcode)
	} else {
		// EVEX E4 uses qword fault-suppression lanes, including m64bcst;
		// only each qword's low dword participates in the multiplication.
		var a, b string
		a, err = c.loadDwordMultiplyEvenLanes(first, form.byteWidth, form.spec.memoryBits, form.broadcast, mask)
		if err == nil {
			b, err = c.loadDwordMultiplyEvenLanes(second, form.byteWidth, form.spec.memoryBits, false, "")
		}
		if err == nil {
			a = c.extendDwordMultiplyLanes(a, lanes, form.spec.signed)
			b = c.extendDwordMultiplyLanes(b, lanes, form.spec.signed)
			product := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul <%d x i64> %s, %s\n", product, lanes, a, b)
			result = "%" + product
		}
	}
	if err != nil {
		return true, false, err
	}
	if form.mask >= 0 {
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(destination, form.byteWidth, 64, false)
			if err != nil {
				return true, false, err
			}
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, 64, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", out, lanes, result, form.byteWidth)
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

func isAMD64XRegOperand(op Operand) bool {
	return op.Kind == OpReg && isAMD64XReg(op.Reg)
}

func (c *amd64Ctx) loadDwordMultiplyEvenLanes(op Operand, byteWidth, memoryBits int, broadcast bool, mask string) (string, error) {
	lanes := byteWidth / 8
	qwords, err := c.loadX86PackedShiftLanes(op, byteWidth, memoryBits, broadcast, mask)
	if err != nil {
		return "", err
	}
	even := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc <%d x i64> %s to <%d x i32>\n", even, lanes, qwords, lanes)
	return "%" + even, nil
}

func (c *amd64Ctx) extendDwordMultiplyLanes(value string, lanes int, signed bool) string {
	extended := c.newTmp()
	op := "zext"
	if signed {
		op = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i32> %s to <%d x i64>\n", extended, op, lanes, value, lanes)
	return "%" + extended
}

func (c *amd64Ctx) lowDwordFromI64(value string) string {
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", low, value)
	return "%" + low
}

func (c *amd64Ctx) extendDwordScalar(value string, signed bool) string {
	extended := c.newTmp()
	op := "zext"
	if signed {
		op = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", extended, op, value)
	return "%" + extended
}
