package plan9asm

import "fmt"

// lowerBZHI implements Go 1.27's complete _ybextrl operand row for BZHIL/Q:
// register index, register/memory source, and register destination.
func (c *amd64Ctx) lowerBZHI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	bits := 0
	switch op {
	case "BZHIL":
		bits = 32
	case "BZHIQ":
		bits = 64
	default:
		return false, false, nil
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects register index, register/memory source, and register destination: %q", c.goarch, op, ins.Raw)
	}
	index, source, destination := ins.Args[0], ins.Args[1], ins.Args[2]
	if index.Kind != OpReg || !isX86YrlRegisterForArch(index.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s index is outside Go 1.27's Yrl class: %q", c.goarch, op, ins.Raw)
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
	indexValue, err := c.evalIntSized(index, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}
	indexLowByte := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, 255\n", indexLowByte, typ, indexValue)
	indexInRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %d\n", indexInRange, typ, indexLowByte, bits)
	safeIndex := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", safeIndex, typ, indexLowByte, bits-1)
	one := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", one, typ, safeIndex)
	partialMask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, -1\n", partialMask, typ, one)
	mask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s -1\n", mask, indexInRange, typ, partialMask, typ)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, sourceValue, mask)
	if err := c.storeRegSized(destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", carry, indexInRange)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	return true, false, nil
}
