package plan9asm

import "fmt"

// lowerMOVBE implements both rows of Go 1.27's ymovbe table: memory to
// general register and general register to memory, for W/L/Q widths.
func (c *amd64Ctx) lowerMOVBE(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86MOVBEProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	typ := amd64IntegerTypeForBits(form.bits)
	value, err := c.evalSizedNativeGPSource(form.source, typ, ins.x86AddressBits)
	if err != nil {
		return true, false, err
	}
	swapped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.bswap.%s(%s %s)\n", swapped, typ, typ, typ, value)
	if !form.store {
		return true, false, c.storeRegSized(form.destination.Reg, typ, "%"+swapped)
	}
	return true, false, c.storeMOVBEMemory(form.destination, typ, "%"+swapped)
}

func (c *amd64Ctx) storeMOVBEMemory(destination Operand, typ LLVMType, value string) error {
	switch destination.Kind {
	case OpMem:
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(destination)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	case OpFP:
		return c.storeFPResult(destination.FPOffset, typ, value)
	case OpSym:
		pointer, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, ptr %s, align 1\n", typ, value, pointer)
		return nil
	default:
		return fmt.Errorf("MOVBE destination is not memory: %s", destination.String())
	}
}
