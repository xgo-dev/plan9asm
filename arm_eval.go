package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func (c *armCtx) imm32(n int64) string {
	return strconv.FormatInt(n, 10)
}

func (c *armCtx) addrI32(mem MemRef, postInc bool) (addr string, base Reg, inc int64, err error) {
	if mem.OffRaw != "" && !armNamedStackOffset(mem) {
		return "", "", 0, fmt.Errorf("arm: unresolved address offset %q requires a typed address form", mem.OffRaw)
	}
	base = mem.Base
	baseVal, err := c.loadReg(base)
	if err != nil {
		return "", "", 0, err
	}
	off := mem.Off
	if postInc {
		inc = off
		off = 0
	}
	sum := baseVal
	if mem.Index != "" {
		idxVal, err := c.loadReg(mem.Index)
		if err != nil {
			return "", "", 0, err
		}
		if mem.Scale != 0 && mem.Scale != 1 {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", t, idxVal, c.imm32(mem.Scale))
			idxVal = "%" + t
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", t, sum, idxVal)
		sum = "%" + t
	}
	if off != 0 {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", t, sum, c.imm32(off))
		sum = "%" + t
	}
	return sum, base, inc, nil
}

func (c *armCtx) updatePostInc(base Reg, inc int64) error {
	if inc == 0 {
		return nil
	}
	baseVal, err := c.loadReg(base)
	if err != nil {
		return err
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", t, baseVal, c.imm32(inc))
	return c.storeReg(base, "%"+t)
}

func (c *armCtx) loadMem(mem MemRef, bits int, postInc bool, signed bool) (string, error) {
	addr, base, inc, err := c.addrI32(mem, postInc)
	if err != nil {
		return "", err
	}
	out, err := c.loadMemAddress(addr, bits, signed)
	if err == nil {
		err = c.updatePostInc(base, inc)
	}
	return out, err
}

func (c *armCtx) loadMemAddress(addr string, bits int, signed bool) (string, error) {
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pt, addr)
	ptr := "%" + pt

	var out string
	switch bits {
	case 64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", t, ptr)
		out = "%" + t
	case 32:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s\n", t, ptr)
		out = "%" + t
	case 16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", t, ptr)
		e := c.newTmp()
		if signed {
			fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i32\n", e, t)
		} else {
			fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i32\n", e, t)
		}
		out = "%" + e
	case 8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s\n", t, ptr)
		e := c.newTmp()
		if signed {
			fmt.Fprintf(c.b, "  %%%s = sext i8 %%%s to i32\n", e, t)
		} else {
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i32\n", e, t)
		}
		out = "%" + e
	default:
		return "", fmt.Errorf("arm: unsupported load bits %d", bits)
	}
	return out, nil
}

func (c *armCtx) storeMem(mem MemRef, bits int, postInc bool, v32 string) error {
	addr, base, inc, err := c.addrI32(mem, postInc)
	if err != nil {
		return err
	}
	if err := c.storeMemAddress(addr, bits, v32); err != nil {
		return err
	}
	return c.updatePostInc(base, inc)
}

func (c *armCtx) storeMemAddress(addr string, bits int, v32 string) error {
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pt, addr)
	ptr := "%" + pt
	switch bits {
	case 64:
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v32, ptr)
	case 32:
		fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n", v32, ptr)
	case 16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", t, v32)
		fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", t, ptr)
	case 8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", t, v32)
		fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s\n", t, ptr)
	default:
		return fmt.Errorf("arm: unsupported store bits %d", bits)
	}
	return nil
}

func (c *armCtx) eval32(op Operand, postInc bool) (string, error) {
	switch op.Kind {
	case OpImm:
		if op.ImmRaw != "" {
			return "", fmt.Errorf("arm: unresolved symbolic immediate %q", op.ImmRaw)
		}
		return c.imm32(op.Imm), nil
	case OpReg:
		return c.loadReg(op.Reg)
	case OpRegShift:
		return c.evalShift(op)
	case OpFP:
		return c.evalFPValue32(op)
	case OpFPAddr:
		return c.evalFPAddr32(op)
	case OpMem:
		return c.loadMem(op.Mem, 32, postInc, false)
	case OpSym:
		sym := strings.TrimSpace(op.Sym)
		if strings.HasPrefix(sym, "$") {
			sym = strings.TrimPrefix(sym, "$")
		}
		if mem, ok := parseMem(sym); ok {
			addr, _, _, err := c.addrI32(mem, false)
			if err != nil {
				return "", err
			}
			return addr, nil
		}
		p, err := c.ptrFromSB(sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, p)
		return "%" + t, nil
	case OpIdent:
		t := c.newTmp()
		switch strings.ToUpper(op.Ident) {
		case "CPSR":
			fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", t, "mrs $0, cpsr", "=r,~{memory}")
			return "%" + t, nil
		case "FPCR", "FPSR":
			fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", t, "vmrs $0, fpscr", "=r,~{memory}")
			return "%" + t, nil
		}
		return "0", nil
	default:
		return "", fmt.Errorf("arm: unsupported operand for i32: %s", op.String())
	}
}

func (c *armCtx) evalShift(op Operand) (string, error) {
	base, err := c.loadReg(op.Reg)
	if err != nil {
		return "", err
	}
	var sh string
	if op.ShiftReg != "" {
		sh, err = c.loadReg(op.ShiftReg)
		if err != nil {
			return "", err
		}
	} else {
		sh = c.imm32(op.ShiftAmount)
	}
	t := c.newTmp()
	switch op.ShiftOp {
	case ShiftLeft:
		fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %s\n", t, base, sh)
	case ShiftRight:
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %s\n", t, base, sh)
	case ShiftArith:
		fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, %s\n", t, base, sh)
	case ShiftRotate:
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %s)\n", t, base, base, sh)
	default:
		return "", fmt.Errorf("arm: unsupported shift op %q", op.ShiftOp)
	}
	return "%" + t, nil
}

func (c *armCtx) evalFPValue32(op Operand) (string, error) {
	slot, ok := c.fpParams[op.FPOffset]
	if !ok {
		for base, candidate := range c.fpParams {
			if candidate.Type != I64 && candidate.Type != LLVMType("double") || op.FPOffset != base+4 {
				continue
			}
			p := c.fpParamAlloca[base]
			if p == "" {
				return "", fmt.Errorf("arm: missing FP param alloca for +%d(FP)", base)
			}
			full := c.newTmp()
			fullValue := "%" + full
			hi := c.newTmp()
			word := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", full, candidate.Type, p)
			if candidate.Type == LLVMType("double") {
				bits := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", bits, fullValue)
				fullValue = "%" + bits
			}
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", hi, fullValue)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", word, hi)
			return "%" + word, nil
		}
		return "", fmt.Errorf("arm: unsupported FP param slot: %s", op.String())
	}
	if slot.Index < 0 || slot.Index >= len(c.sig.Args) {
		return "", fmt.Errorf("arm: FP slot %s invalid arg index %d", op.String(), slot.Index)
	}
	arg := fmt.Sprintf("%%arg%d", slot.Index)
	if p := c.fpParamAlloca[op.FPOffset]; p != "" {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", t, slot.Type, p)
		arg = "%" + t
	} else if fields := frameSlotFields(slot); len(fields) != 0 {
		aggTy := c.sig.Args[slot.Index]
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s%s\n", t, aggTy, arg, frameSlotExtractSuffix(slot))
		arg = "%" + t
	}
	switch slot.Type {
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, arg)
		return "%" + t, nil
	case I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", t, arg)
		return "%" + t, nil
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i32\n", t, arg)
		return "%" + t, nil
	case I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", t, arg)
		return "%" + t, nil
	case I32:
		return arg, nil
	case I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, arg)
		return "%" + t, nil
	case LLVMType("double"):
		bits := c.newTmp()
		word := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", bits, arg)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", word, bits)
		return "%" + word, nil
	default:
		return "", fmt.Errorf("arm: unsupported FP slot type %q", slot.Type)
	}
}

func (c *armCtx) evalFPAddr32(op Operand) (string, error) {
	ptr, resultOffset, isResult, ok := c.armFramePointer(op.FPOffset, 0)
	if ok {
		if isResult {
			c.markFPResultAddrTaken(resultOffset)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, ptr)
		return "%" + t, nil
	}
	if op.FPName == "argframe" {
		// Dynamic reflect/callback stubs use $argframe(FP) without a statically
		// declared argument frame. An ordinary LLVM function signature cannot
		// recover that caller-owned address. Keep corpus/object lowering permissive,
		// as the ARM64 lowering does, while executable ABI tests remain responsible
		// for using only addressable, modeled slots.
		return "0", nil
	}
	if strings.EqualFold(op.FPName, "sp") && op.FPOffset == -4 {
		// runtime.vdsoCall spells the caller's stack pointer as $sp-4(FP).
		// An ordinary LLVM function signature does not expose that caller-owned
		// address. Match the explicit argframe context fallback above so corpus
		// and object lowering remain possible; executable ABI coverage must not
		// treat this placeholder as an addressable modeled frame slot.
		return "0", nil
	}
	return "", fmt.Errorf("arm: unsupported FP addr slot: %s", op.String())
}

func armFrameTypeSize(typ LLVMType) int64 {
	switch typ {
	case I1, I8:
		return 1
	case I16:
		return 2
	case I32, Ptr, LLVMType("float"):
		return 4
	case I64, LLVMType("double"):
		return 8
	default:
		// Frame slots are normally scalar leaves. Preserve the established
		// conservative aggregate fallback used by the x86 classic-frame model.
		return 16
	}
}

// armFramePointer resolves exact and interior classic-frame offsets to the
// backing alloca. accessBytes == 0 forms an address; positive sizes additionally
// prove that the requested load/store remains inside that modeled slot.
func (c *armCtx) armFramePointer(off, accessBytes int64) (ptr string, base int64, isResult, ok bool) {
	type candidate struct {
		slot     FrameSlot
		ptr      string
		isResult bool
	}
	candidates := make([]candidate, 0, len(c.sig.Frame.Params)+len(c.fpResults))
	for _, slot := range c.sig.Frame.Params {
		if p := c.fpParamAlloca[slot.Offset]; p != "" {
			candidates = append(candidates, candidate{slot: slot, ptr: p})
		}
	}
	for _, slot := range c.fpResults {
		if p := c.fpResAllocaIdx[slot.Index]; p != "" {
			candidates = append(candidates, candidate{slot: slot, ptr: p, isResult: true})
		}
	}
	// Prefer an exact slot when one starts at the same offset as the end of an
	// earlier slot.
	for pass := 0; pass < 2; pass++ {
		for _, candidate := range candidates {
			size := armFrameTypeSize(candidate.slot.Type)
			exact := off == candidate.slot.Offset
			inside := off >= candidate.slot.Offset && off < candidate.slot.Offset+size
			if (pass == 0 && !exact) || (pass == 1 && exact) || !inside {
				continue
			}
			if accessBytes > 0 && off+accessBytes > candidate.slot.Offset+size {
				continue
			}
			resolved := candidate.ptr
			if delta := off - candidate.slot.Offset; delta != 0 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i32 %d\n", t, resolved, delta)
				resolved = "%" + t
			}
			return resolved, candidate.slot.Offset, candidate.isResult, true
		}
	}
	return "", 0, false, false
}

func (c *armCtx) loadARMFrameBits(off int64, bits int) (string, error) {
	ptr, _, _, ok := c.armFramePointer(off, int64(bits/8))
	if !ok {
		return "", fmt.Errorf("arm: unsupported %d-bit FP frame load at +%d(FP)", bits, off)
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s\n", value, bits, ptr)
	return "%" + value, nil
}

func (c *armCtx) storeARMFrameBits(off int64, bits int, value string) error {
	ptr, resultOffset, isResult, ok := c.armFramePointer(off, int64(bits/8))
	if !ok {
		return fmt.Errorf("arm: unsupported %d-bit FP frame store at +%d(FP)", bits, off)
	}
	fmt.Fprintf(c.b, "  store i%d %s, ptr %s\n", bits, value, ptr)
	if isResult {
		c.markFPResultWritten(resultOffset)
	}
	return nil
}
