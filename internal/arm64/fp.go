package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *arm64Ctx) fpResultSlotByOffset(off int64) (slot asm.FrameSlot, ok bool) {
	for _, s := range c.fpResults {
		if s.Offset == off {
			return s, true
		}
	}
	return asm.FrameSlot{}, false
}

func (c *arm64Ctx) markFPResultWritten(off int64) {
	if s, ok := c.fpResultSlotByOffset(off); ok {
		c.fpResWritten[s.Index] = true
	}
}

func (c *arm64Ctx) markFPResultAddrTaken(off int64) {
	if s, ok := c.fpResultSlotByOffset(off); ok {
		c.fpResAddrTaken[s.Index] = true
	}
}

func (c *arm64Ctx) storeFPResult64(off int64, v64 string) error {
	slot, ok := c.fpResAllocaOff[off]
	if !ok {
		return fmt.Errorf("arm64: unsupported FP result slot +%d(FP)", off)
	}
	// Find the element type via FrameSlot.
	meta, found := c.fpResultSlotByOffset(off)
	if !found {
		return fmt.Errorf("arm64: missing FP result metadata for +%d(FP)", off)
	}
	ty := meta.Type

	switch string(ty) {
	case "i64":
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v64, slot)
		c.markFPResultWritten(off)
		return nil
	case "i32", "i16", "i8", "i1":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		fmt.Fprintf(c.b, "  store %s %%%s, ptr %s\n", ty, t, slot)
		c.markFPResultWritten(off)
		return nil
	case "ptr":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v64)
		fmt.Fprintf(c.b, "  store ptr %%%s, ptr %s\n", t, slot)
		c.markFPResultWritten(off)
		return nil
	case "double":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, v64)
		fmt.Fprintf(c.b, "  store double %%%s, ptr %s\n", t, slot)
		c.markFPResultWritten(off)
		return nil
	case "float":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v64)
		b := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", b, t)
		fmt.Fprintf(c.b, "  store float %%%s, ptr %s\n", b, slot)
		c.markFPResultWritten(off)
		return nil
	default:
		return fmt.Errorf("arm64: unsupported FP result slot type %q", ty)
	}
}

func (c *arm64Ctx) loadFPResult(slot asm.FrameSlot) (val string, err error) {
	p, ok := c.fpResAllocaIdx[slot.Index]
	if !ok {
		return "", fmt.Errorf("arm64: missing FP result alloca for index %d", slot.Index)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", t, slot.Type, p)
	return "%" + t, nil
}

func (c *arm64Ctx) loadRetSlotFallback(slot asm.FrameSlot) (string, error) {
	if slot.Index < 0 || slot.Index > 31 {
		return asm.LLVMZeroValue(slot.Type), nil
	}
	r := asm.Reg(fmt.Sprintf("R%d", slot.Index))
	v64, err := c.loadReg(r)
	if err != nil {
		return "", err
	}
	switch slot.Type {
	case asm.I64:
		return v64, nil
	case asm.I32, asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, slot.Type)
		return "%" + t, nil
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v64)
		return "%" + t, nil
	case asm.LLVMType("double"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, v64)
		return "%" + t, nil
	case asm.LLVMType("float"):
		t32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t32, v64)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", t, t32)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: unsupported fallback return type %q", slot.Type)
	}
}
