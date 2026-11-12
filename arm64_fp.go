package plan9asm

import "fmt"

func (c *arm64Ctx) fpResultSlotByOffset(off int64) (slot FrameSlot, ok bool) {
	for _, s := range c.fpResults {
		if s.Offset == off {
			return s, true
		}
	}
	return FrameSlot{}, false
}

func (c *arm64Ctx) loadFPParameter(slot FrameSlot) (string, error) {
	p, ok := c.fpParamAlloca[slot.Offset]
	if !ok {
		return "", fmt.Errorf("arm64: missing FP parameter alloca for +%d(FP)", slot.Offset)
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", value, slot.Type, p)
	return "%" + value, nil
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
	meta, isResult := c.fpResultSlotByOffset(off)
	if !ok {
		slot, ok = c.fpParamAlloca[off]
		var found bool
		meta, found = c.fpParams[off]
		if !ok || !found {
			return fmt.Errorf("arm64: unsupported FP slot +%d(FP)", off)
		}
	}
	if meta.Type == "" {
		return fmt.Errorf("arm64: unsupported FP slot +%d(FP)", off)
	}
	ty := meta.Type

	switch string(ty) {
	case "i64":
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v64, slot)
		if isResult {
			c.markFPResultWritten(off)
		}
		return nil
	case "i32", "i16", "i8", "i1":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		fmt.Fprintf(c.b, "  store %s %%%s, ptr %s\n", ty, t, slot)
		if isResult {
			c.markFPResultWritten(off)
		}
		return nil
	case "ptr":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v64)
		fmt.Fprintf(c.b, "  store ptr %%%s, ptr %s\n", t, slot)
		if isResult {
			c.markFPResultWritten(off)
		}
		return nil
	case "double":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, v64)
		fmt.Fprintf(c.b, "  store double %%%s, ptr %s\n", t, slot)
		if isResult {
			c.markFPResultWritten(off)
		}
		return nil
	case "float":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v64)
		b := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", b, t)
		fmt.Fprintf(c.b, "  store float %%%s, ptr %s\n", b, slot)
		if isResult {
			c.markFPResultWritten(off)
		}
		return nil
	default:
		return fmt.Errorf("arm64: unsupported FP result slot type %q", ty)
	}
}

func (c *arm64Ctx) loadFPResult(slot FrameSlot) (val string, err error) {
	p, ok := c.fpResAllocaIdx[slot.Index]
	if !ok {
		return "", fmt.Errorf("arm64: missing FP result alloca for index %d", slot.Index)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", t, slot.Type, p)
	return "%" + t, nil
}

func (c *arm64Ctx) loadRetSlotFallback(slot FrameSlot) (string, error) {
	if slot.Index < 0 || slot.Index > 31 {
		return llvmZeroValue(slot.Type), nil
	}
	r := Reg(fmt.Sprintf("R%d", slot.Index))
	v64, err := c.loadReg(r)
	if err != nil {
		return "", err
	}
	switch slot.Type {
	case I64:
		return v64, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, slot.Type)
		return "%" + t, nil
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v64)
		return "%" + t, nil
	case LLVMType("double"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, v64)
		return "%" + t, nil
	case LLVMType("float"):
		t32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t32, v64)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", t, t32)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: unsupported fallback return type %q", slot.Type)
	}
}
