package plan9asm

import "fmt"

// lowerBEXTR implements Go 1.27's complete _ybextrl operand row for BEXTRL/Q:
// register control, register/memory source, and register destination.
func (c *amd64Ctx) lowerBEXTR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86BEXTRProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	bits := form.bits
	typ := amd64IntegerTypeForBits(bits)
	controlValue, err := c.evalIntSized(form.control, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, err := c.evalScalarBitFieldSource(ins, form, typ)
	if err != nil {
		return true, false, err
	}
	start := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, 255\n", start, typ, controlValue)
	lengthShift := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, 8\n", lengthShift, typ, controlValue)
	length := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 255\n", length, typ, lengthShift)
	startOK := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %d\n", startOK, typ, start, bits)
	safeStart := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %d\n", safeStart, startOK, typ, start, typ, bits-1)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", shifted, typ, sourceValue, safeStart)
	rawLength := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", rawLength, startOK, typ, length, typ)
	remaining := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %d, %%%s\n", remaining, typ, bits, safeStart)
	useRawLength := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", useRawLength, typ, rawLength, remaining)
	effectiveLength := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %%%s\n", effectiveLength, useRawLength, typ, rawLength, typ, remaining)
	isFullWidth := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, %d\n", isFullWidth, typ, effectiveLength, bits)
	safeLength := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", safeLength, typ, effectiveLength, bits-1)
	one := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", one, typ, safeLength)
	partialMask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, -1\n", partialMask, typ, one)
	mask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s -1, %s %%%s\n", mask, isFullWidth, typ, typ, partialMask)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", result, typ, shifted, mask)
	if err := c.storeRegSized(form.destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return true, false, nil
}

func (c *amd64Ctx) evalScalarBitFieldSource(ins Instr, form x86ScalarBitFieldForm, typ LLVMType) (string, error) {
	if form.source.Kind == OpFP && x86ResultNamedPredicateInstruction(ins) {
		if value, handled, err := c.loadIntegerFPBytesMode(form.source.FPOffset, typ, true); handled || err != nil {
			return value, err
		}
	}
	if isAMD64MemoryOperand(form.source) && form.source.Kind != OpFP &&
		(x86OrdinaryNativeMemoryOperand(form.source, c.goarch) ||
			x86CallerMemoryCertified(ins, 1) || c.fixedLocalMemoryCertified(ins, 1)) {
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return "", fmt.Errorf("%w: %s needs its original native address size", ErrProbeNeedsContext, ins.Op)
		}
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		// Preserve the full physical read even for zero controls/dead outputs.
		// Alignment, bounds and pointee validity are not optimizer assumptions.
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, pointerType, pointer)
		return "%" + value, nil
	}
	return c.evalIntSized(form.source, typ)
}
