package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *armCtx) fpResultSlotByOffset(off int64) (asm.FrameSlot, bool) {
	for _, s := range c.fpResults {
		if s.Offset == off {
			return s, true
		}
	}
	return asm.FrameSlot{}, false
}

func (c *armCtx) markFPResultWritten(off int64) {
	if s, ok := c.fpResultSlotByOffset(off); ok {
		c.fpResWritten[s.Index] = true
	}
}

func (c *armCtx) markFPResultAddrTaken(off int64) {
	if s, ok := c.fpResultSlotByOffset(off); ok {
		c.fpResAddrTaken[s.Index] = true
	}
}

func (c *armCtx) storeFPResult32(off int64, v32 string) error {
	for _, meta := range c.fpResults {
		if meta.Type != asm.I64 || (off != meta.Offset && off != meta.Offset+4) {
			continue
		}
		slot := c.fpResAllocaIdx[meta.Index]
		if slot == "" {
			return fmt.Errorf("arm: missing FP result alloca for index %d", meta.Index)
		}
		old := c.newTmp()
		word := c.newTmp()
		cleared := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", old, slot)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", word, v32)
		inserted := "%" + word
		if off == meta.Offset {
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, -4294967296\n", cleared, old)
		} else {
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 4294967295\n", cleared, old)
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", shifted, word)
			inserted = "%" + shifted
		}
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, cleared, inserted)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", merged, slot)
		c.fpResWritten[meta.Index] = true
		return nil
	}
	slot, ok := c.fpResAllocaOff[off]
	if !ok {
		return fmt.Errorf("arm: unsupported FP result slot +%d(FP)", off)
	}
	meta, found := c.fpResultSlotByOffset(off)
	if !found {
		return fmt.Errorf("arm: missing FP result metadata for +%d(FP)", off)
	}
	if err := c.storeFPScalar32(meta.Type, slot, v32); err != nil {
		return fmt.Errorf("arm: unsupported FP result slot type %q", meta.Type)
	}
	c.markFPResultWritten(off)
	return nil
}

func (c *armCtx) storeFP32(off int64, v32 string) error {
	if meta, ok := c.fpParams[off]; ok {
		slot := c.fpParamAlloca[off]
		if slot == "" {
			return fmt.Errorf("arm: missing FP param alloca for +%d(FP)", off)
		}
		if err := c.storeFPScalar32(meta.Type, slot, v32); err != nil {
			return fmt.Errorf("arm: unsupported FP param slot type %q", meta.Type)
		}
		return nil
	}
	return c.storeFPResult32(off, v32)
}

func (c *armCtx) storeFPScalar32(typ asm.LLVMType, slot, v32 string) error {
	switch typ {
	case asm.I32:
		fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n", v32, slot)
	case asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", t, v32, typ)
		fmt.Fprintf(c.b, "  store %s %%%s, ptr %s\n", typ, t, slot)
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", t, v32)
		fmt.Fprintf(c.b, "  store ptr %%%s, ptr %s\n", t, slot)
	case asm.I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v32)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", t, slot)
	default:
		return fmt.Errorf("unsupported type %q", typ)
	}
	return nil
}

func (c *armCtx) loadFPResult(slot asm.FrameSlot) (string, error) {
	p, ok := c.fpResAllocaIdx[slot.Index]
	if !ok {
		return "", fmt.Errorf("arm: missing FP result alloca for index %d", slot.Index)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", t, slot.Type, p)
	return "%" + t, nil
}

func (c *armCtx) loadRetSlotFallback(slot asm.FrameSlot) (string, error) {
	v32, err := c.loadReg(asm.Reg("R0"))
	if err != nil {
		return "", err
	}
	switch slot.Type {
	case asm.I32:
		return v32, nil
	case asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", t, v32, slot.Type)
		return "%" + t, nil
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", t, v32)
		return "%" + t, nil
	case asm.I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v32)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm: unsupported fallback return type %q", slot.Type)
	}
}
