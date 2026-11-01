package plan9asm

import "fmt"

func (c *amd64Ctx) x87NativeFloatingMoveResultStep(ins Instr, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86X87ValueProperties(ins, arch)
	if !known || form.spec.kind != x86X87FloatMove {
		return false, false
	}
	if err != nil || !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return false, true
	}
	return x86ResultX87ValueStepWithMemory(ins, state, owned, resultOffset, arch, false, true)
}

// Both native floating widths use exact unaligned volatile accesses. Dead
// moves retain their memory effect; continuing one supplies no later backing,
// bounds, alignment or caller-storage fact.
func (c *amd64Ctx) loadX87FloatingMove(source Operand, bits int) (string, error) {
	if !x86RegisterAddressedNativeMemoryOperand(source, c.goarch) {
		if bits == 32 {
			return c.evalF32(source)
		}
		return c.evalX87F64(source)
	}
	pointer, pointerType, err := c.x87MemoryPointer(source)
	if err != nil {
		return "", err
	}
	typ := "double"
	if bits == 32 {
		typ = "float"
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, pointerType, pointer)
	return "%" + value, nil
}

func (c *amd64Ctx) storeX87NativeFloatingMove(destination Operand, typ LLVMType, value string) (bool, error) {
	if !x86RegisterAddressedNativeMemoryOperand(destination, c.goarch) {
		return false, nil
	}
	pointer, pointerType, err := c.x87MemoryPointer(destination)
	if err != nil {
		return true, err
	}
	fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
	return true, nil
}
