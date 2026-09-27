package plan9asm

import "fmt"

// lowerADX implements ADCXL/Q and ADOXL/Q. All four opcodes use Go 1.27's
// yml_rl row: register/memory source and register destination. ADCX consumes
// and updates CF; ADOX independently consumes and updates OF.
func (c *amd64Ctx) lowerADX(op Op, ins Instr) (ok bool, terminated bool, err error) {
	bits := 0
	flagSlot := ""
	switch op {
	case "ADCXL":
		bits, flagSlot = 32, c.flagsCFSlot
	case "ADCXQ":
		bits, flagSlot = 64, c.flagsCFSlot
	case "ADOXL":
		bits, flagSlot = 32, c.flagsOFSlot
	case "ADOXQ":
		bits, flagSlot = 64, c.flagsOFSlot
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
	sourceValue, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}
	destinationValue, err := c.evalIntSized(destination, typ)
	if err != nil {
		return true, false, err
	}
	carryIn := c.loadFlag(flagSlot)
	carryValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", carryValue, carryIn, typ)
	sum := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", sum, typ, destinationValue, sourceValue)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", result, typ, sum, carryValue)
	carryFromOperands := c.newTmp()
	carryFromInput := c.newTmp()
	carryOut := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %s\n", carryFromOperands, typ, sum, destinationValue)
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %%%s, %%%s\n", carryFromInput, typ, result, sum)
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", carryOut, carryFromOperands, carryFromInput)
	if err := c.storeRegSized(destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carryOut, flagSlot)
	return true, false, nil
}
