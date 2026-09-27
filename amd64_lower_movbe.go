package plan9asm

import "fmt"

// lowerMOVBE implements both rows of Go 1.27's ymovbe table: memory to
// general register and general register to memory, for W/L/Q widths.
func (c *amd64Ctx) lowerMOVBE(op Op, ins Instr) (ok bool, terminated bool, err error) {
	typ := LLVMType("")
	switch op {
	case "MOVBEW":
		typ = I16
	case "MOVBEL":
		typ = I32
	case "MOVBEQ", "MOVBEQQ":
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", op, ins.Raw)
		}
		typ = I64
	default:
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects one memory and one general-register operand: %q", c.goarch, op, ins.Raw)
	}
	source, destination := ins.Args[0], ins.Args[1]
	sourceRegister := source.Kind == OpReg && isX86YrlRegisterForArch(source.Reg, c.goarch)
	destinationRegister := destination.Kind == OpReg && isX86YrlRegisterForArch(destination.Reg, c.goarch)
	sourceMemory := isAMD64MemoryOperand(source)
	destinationMemory := isAMD64MemoryOperand(destination)
	if !((sourceMemory && destinationRegister) || (sourceRegister && destinationMemory)) {
		return true, false, fmt.Errorf("%s %s operands are outside Go 1.27's Ym,Yrl/Yrl,Ym rows: %q", c.goarch, op, ins.Raw)
	}

	value, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}
	swapped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.bswap.%s(%s %s)\n", swapped, typ, typ, typ, value)
	if destinationRegister {
		return true, false, c.storeRegSized(destination.Reg, typ, "%"+swapped)
	}
	return true, false, c.storeMOVBEMemory(destination, typ, "%"+swapped)
}

func (c *amd64Ctx) storeMOVBEMemory(destination Operand, typ LLVMType, value string) error {
	switch destination.Kind {
	case OpMem:
		pointer, pointerType, err := c.ptrFromMem(destination.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	case OpFP:
		return c.storeFPResult(destination.FPOffset, typ, value)
	case OpSym:
		pointer, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", typ, value, pointer)
		return nil
	default:
		return fmt.Errorf("MOVBE destination is not memory: %s", destination.String())
	}
}
