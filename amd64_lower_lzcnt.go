package plan9asm

import "fmt"

// lowerLeadingZeroCount implements the complete LZCNTW/L/Q yml_rl family.
func (c *amd64Ctx) lowerLeadingZeroCount(op Op, ins Instr) (ok bool, terminated bool, err error) {
	bits := 0
	switch op {
	case "LZCNTW":
		bits = 16
	case "LZCNTL":
		bits = 32
	case "LZCNTQ":
		bits = 64
	default:
		return false, false, nil
	}
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", op, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects register/memory source and register destination: %q", c.goarch, op, ins.Raw)
	}
	source, destination := ins.Args[0], ins.Args[1]
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
	value, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}
	count := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.%s(%s %s, i1 false)\n", count, typ, typ, typ, value)
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", carry, typ, value)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zero, typ, count)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	if err := c.storeRegSized(destination.Reg, typ, "%"+count); err != nil {
		return true, false, err
	}
	return true, false, nil
}
