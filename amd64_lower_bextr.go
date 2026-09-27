package plan9asm

import "fmt"

// lowerBEXTR implements Go 1.27's complete _ybextrl operand row for BEXTRL/Q:
// register control, register/memory source, and register destination.
func (c *amd64Ctx) lowerBEXTR(op Op, ins Instr) (ok bool, terminated bool, err error) {
	bits := 0
	switch op {
	case "BEXTRL":
		bits = 32
	case "BEXTRQ":
		bits = 64
	default:
		return false, false, nil
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects register control, register/memory source, and register destination: %q", c.goarch, op, ins.Raw)
	}
	control, source, destination := ins.Args[0], ins.Args[1], ins.Args[2]
	if control.Kind != OpReg || !isX86YrlRegisterForArch(control.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s control is outside Go 1.27's Yrl class: %q", c.goarch, op, ins.Raw)
	}
	if source.Kind == OpReg {
		if !isX86YrlRegisterForArch(source.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
	}
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yrl class: %q", c.goarch, op, ins.Raw)
	}

	typ := amd64IntegerTypeForBits(bits)
	controlValue, err := c.evalIntSized(control, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, err := c.evalIntSized(source, typ)
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
	if err := c.storeRegSized(destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return true, false, nil
}
