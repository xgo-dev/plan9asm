package plan9asm

import "fmt"

// boundFPAddress addresses a declared field's backing storage, never its
// current value. An unbound source address needs a physical frame contract;
// inventing a zero pointer or extending an alloca into padding is not one.
func (c *amd64Ctx) boundFPAddress(off int64) (string, error) {
	slot, result, ok := c.fpVectorSlot(off)
	if !ok {
		return "", fmt.Errorf("%w: %s FP address at +%d(FP) requires bound typed frame storage", ErrProbeNeedsContext, c.goarch, off)
	}
	if x86FrameScalarBytes(slot.Type, c.goarch) == 0 {
		// The vector lookup's conservative aggregate-size fallback is not a
		// storage-width proof. Scalar bool fields use canonical i8 backing.
		return "", fmt.Errorf("%w: %s FP address at +%d(FP) lacks a scalar byte-storage contract for %s", ErrProbeNeedsContext, c.goarch, off, slot.Type)
	}
	if result {
		c.markFPResultAddrTaken(slot.Offset)
	}
	var pointer string
	if c.classicFrame != "" {
		pointer = c.classicFramePtr(off)
	} else {
		if result {
			pointer, _, ok = c.fpResultAlloca(slot.Offset)
		} else {
			pointer = c.fpParamAlloca[slot.Offset]
			ok = pointer != ""
		}
		if !ok {
			return "", fmt.Errorf("%w: %s FP address at +%d(FP) has no backing storage", ErrProbeNeedsContext, c.goarch, off)
		}
		if off != slot.Offset {
			adjusted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds i8, ptr %s, i64 %d\n", adjusted, pointer, off-slot.Offset)
			pointer = "%" + adjusted
		}
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", address, pointer)
	return "%" + address, nil
}

func x86FrameScalarBytes(typ LLVMType, goarch string) int64 {
	switch typ {
	case I1, I8, I16, I32, I64, Ptr, LLVMType("float"), LLVMType("double"):
		pointerSize := int64(8)
		if goarch == "386" {
			pointerSize = 4
		}
		return frameTypeSize(typ, pointerSize)
	default:
		return 0
	}
}
