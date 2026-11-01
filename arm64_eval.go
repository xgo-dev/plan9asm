package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func (c *arm64Ctx) imm64(n int64) string {
	return strconv.FormatInt(n, 10)
}

// addrI64 computes an i64 address from a MemRef.
// If postInc is true, mem.Off is treated as post-increment (address displacement is 0).
func (c *arm64Ctx) addrI64(mem MemRef, postInc bool) (addr string, base Reg, inc int64, err error) {
	if mem.OffRaw != "" && !arm64NamedStackOffset(mem) {
		return "", "", 0, fmt.Errorf("arm64: unresolved memory displacement %q", mem.OffRaw)
	}
	base = mem.Base
	// Register encoding 31 denotes SP in an address operand even when the Go
	// source spells it ZR. RSP is the explicit hardware-stack-pointer spelling;
	// both use the same modeled stack-pointer slot.
	if base == ZR || base == Reg("RSP") {
		base = SP
	}
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
		bits, err := arm64RegisterExtensionWidth(mem.IndexExt)
		if err != nil {
			return "", "", 0, err
		}
		idxVal, err := c.loadRegisterWidth(mem.Index, bits)
		if err != nil {
			return "", "", 0, err
		}
		if mem.IndexExt != "" {
			idxVal, err = c.extendReg64(idxVal, mem.IndexExt)
			if err != nil {
				return "", "", 0, err
			}
		}
		if mem.Scale != 0 && mem.Scale != 1 {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", t, idxVal, c.imm64(mem.Scale))
			idxVal = "%" + t
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", t, sum, idxVal)
		sum = "%" + t
	}
	if off != 0 {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", t, sum, c.imm64(off))
		sum = "%" + t
	}
	return sum, base, inc, nil
}

func (c *arm64Ctx) updatePostInc(base Reg, inc int64) error {
	if inc == 0 {
		return nil
	}
	baseVal, err := c.loadReg(base)
	if err != nil {
		return err
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", t, baseVal, c.imm64(inc))
	return c.storeReg(base, "%"+t)
}

func (c *arm64Ctx) loadMem(mem MemRef, bits int, postInc bool) (string, error) {
	if err := validateARM64MemoryIndex(mem, bits); err != nil {
		return "", err
	}
	addr, base, inc, err := c.addrI64(mem, postInc)
	if err != nil {
		return "", err
	}
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
	ptr := "%" + pt

	switch bits {
	case 64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", t, ptr)
		if err := c.updatePostInc(base, inc); err != nil {
			return "", err
		}
		return "%" + t, nil
	case 32:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s\n", t, ptr)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		if err := c.updatePostInc(base, inc); err != nil {
			return "", err
		}
		return "%" + z, nil
	case 16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", t, ptr)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i64\n", z, t)
		if err := c.updatePostInc(base, inc); err != nil {
			return "", err
		}
		return "%" + z, nil
	case 8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s\n", t, ptr)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", z, t)
		if err := c.updatePostInc(base, inc); err != nil {
			return "", err
		}
		return "%" + z, nil
	default:
		return "", fmt.Errorf("arm64: unsupported load bits %d", bits)
	}
}

func (c *arm64Ctx) storeMem(mem MemRef, bits int, postInc bool, v64 string) error {
	if err := validateARM64MemoryIndex(mem, bits); err != nil {
		return err
	}
	addr, base, inc, err := c.addrI64(mem, postInc)
	if err != nil {
		return err
	}
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
	ptr := "%" + pt

	switch bits {
	case 64:
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v64, ptr)
	case 32, 16, 8, 1:
		dstTy := fmt.Sprintf("i%d", bits)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, dstTy)
		fmt.Fprintf(c.b, "  store %s %%%s, ptr %s\n", dstTy, t, ptr)
	default:
		return fmt.Errorf("arm64: unsupported store bits %d", bits)
	}
	return c.updatePostInc(base, inc)
}

func validateARM64MemoryIndex(mem MemRef, bits int) error {
	if mem.Index == "" {
		return nil
	}
	scale := mem.Scale
	if scale == 0 {
		scale = 1
	}
	if scale != 1 && scale != int64(bits/8) {
		return fmt.Errorf("arm64: invalid %d-bit indexed-memory scale %d", bits, scale)
	}
	return nil
}

func (c *arm64Ctx) eval64(op Operand, postInc bool) (string, error) {
	switch op.Kind {
	case OpImm:
		return c.imm64(op.Imm), nil
	case OpReg:
		return c.loadReg(op.Reg)
	case OpRegExtend:
		bits, err := arm64RegisterExtensionWidth(op.Ext)
		if err != nil {
			return "", err
		}
		v, err := c.loadRegisterWidth(op.Reg, bits)
		if err != nil {
			return "", err
		}
		v, err = c.extendReg64(v, op.Ext)
		if err != nil || op.ShiftOp == "" || op.ShiftAmount == 0 {
			return v, err
		}
		if op.ShiftOp != ShiftLeft || op.ShiftAmount < 0 || op.ShiftAmount > 4 {
			return "", fmt.Errorf("arm64: invalid extended-register shift: %s", op)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", t, v, op.ShiftAmount)
		return "%" + t, nil
	case OpRegShift:
		v, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		if op.ShiftReg != "" {
			return "", fmt.Errorf("arm64: register-based shifts not supported: %s", op)
		}
		if op.ShiftAmount < 0 || op.ShiftAmount > 63 {
			return "", fmt.Errorf("arm64: shift out of range: %s", op)
		}
		t := c.newTmp()
		switch op.ShiftOp {
		case ShiftRight:
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", t, v, op.ShiftAmount)
		case ShiftLeft:
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", t, v, op.ShiftAmount)
		case ShiftArith:
			fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, %d\n", t, v, op.ShiftAmount)
		case ShiftRotate:
			return c.rotateInt(v, "i64", 64, fmt.Sprintf("%d", op.ShiftAmount)), nil
		default:
			return "", fmt.Errorf("arm64: unsupported shift op %q", op.ShiftOp)
		}
		return "%" + t, nil
	case OpFP:
		return c.evalFPValue64(op)
	case OpFPAddr:
		return c.evalFPAddr64(op)
	case OpMem:
		return c.loadMem(op.Mem, 64, postInc)
	case OpSym:
		sym := strings.TrimSpace(op.Sym)
		if strings.HasPrefix(sym, "$") {
			sym = strings.TrimPrefix(sym, "$")
		}
		if mem, ok := parseMem(sym); ok {
			addr, _, _, err := c.addrI64(mem, false)
			if err != nil {
				return "", err
			}
			return addr, nil
		}
		if !strings.Contains(sym, "(SB)") && !strings.Contains(sym, "·") && !strings.Contains(sym, "/") && !strings.Contains(sym, ".") {
			return "0", nil
		}
		p, err := c.ptrFromSB(sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
		return "%" + t, nil
	case OpIdent:
		// Keep parser/lowering permissive for pseudo operands like NZCV.
		return "0", nil
	default:
		return "", fmt.Errorf("arm64: unsupported operand for i64: %s", op.String())
	}
}

func (c *arm64Ctx) eval32(op Operand) (string, error) {
	truncate := func(value string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, value)
		return "%" + t
	}
	switch op.Kind {
	case OpImm:
		return strconv.FormatUint(uint64(uint32(op.Imm)), 10), nil
	case OpReg:
		v, err := c.loadRegisterWidth(op.Reg, 32)
		if err != nil {
			return "", err
		}
		return truncate(v), nil
	case OpRegExtend:
		bits, err := arm64RegisterExtensionWidth(op.Ext)
		if err != nil {
			return "", err
		}
		if bits > 32 {
			bits = 32
		}
		v, err := c.loadRegisterWidth(op.Reg, bits)
		if err != nil {
			return "", err
		}
		var fromType, extend string
		switch op.Ext {
		case ExtendUXTB:
			fromType, extend = "i8", "zext"
		case ExtendUXTH:
			fromType, extend = "i16", "zext"
		case ExtendUXTW, ExtendUXTX:
			fromType = "i32"
		case ExtendSXTB:
			fromType, extend = "i8", "sext"
		case ExtendSXTH:
			fromType, extend = "i16", "sext"
		case ExtendSXTW, ExtendSXTX:
			fromType = "i32"
		default:
			return "", fmt.Errorf("arm64: unsupported register extension %q", op.Ext)
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v, fromType)
		value := "%" + tr
		if extend != "" {
			ex := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %s to i32\n", ex, extend, fromType, value)
			value = "%" + ex
		}
		if op.ShiftOp != "" && op.ShiftAmount != 0 {
			if op.ShiftOp != ShiftLeft || op.ShiftAmount < 0 || op.ShiftAmount > 4 {
				return "", fmt.Errorf("arm64: invalid extended-register shift: %s", op)
			}
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", shifted, value, op.ShiftAmount)
			value = "%" + shifted
		}
		return value, nil
	case OpRegShift:
		if op.ShiftReg != "" || op.ShiftAmount < 0 || op.ShiftAmount > 31 {
			return "", fmt.Errorf("arm64: invalid 32-bit shift: %s", op)
		}
		v, err := c.loadRegisterWidth(op.Reg, 32)
		if err != nil {
			return "", err
		}
		v = truncate(v)
		t := c.newTmp()
		switch op.ShiftOp {
		case ShiftLeft:
			fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", t, v, op.ShiftAmount)
		case ShiftRight:
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", t, v, op.ShiftAmount)
		case ShiftArith:
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, %d\n", t, v, op.ShiftAmount)
		case ShiftRotate:
			return c.rotateInt(v, "i32", 32, fmt.Sprintf("%d", op.ShiftAmount)), nil
		default:
			return "", fmt.Errorf("arm64: unsupported 32-bit shift op %q", op.ShiftOp)
		}
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: unsupported operand for i32: %s", op.String())
	}
}

func (c *arm64Ctx) rotateInt(value, typeName string, bits int, shift string) string {
	inv := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %d, %s\n", inv, typeName, bits, shift)
	masked := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", masked, typeName, inv, bits-1)
	right := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", right, typeName, value, shift)
	left := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", left, typeName, value, masked)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", out, typeName, right, left)
	return "%" + out
}

func arm64RegisterExtensionWidth(ext ExtendOp) (int, error) {
	switch ext {
	case ExtendUXTB, ExtendSXTB:
		return 8, nil
	case ExtendUXTH, ExtendSXTH:
		return 16, nil
	case ExtendUXTW, ExtendSXTW:
		return 32, nil
	case "", ExtendUXTX, ExtendSXTX:
		return 64, nil
	default:
		return 0, fmt.Errorf("arm64: unsupported register extension %q", ext)
	}
}

func (c *arm64Ctx) extendReg64(v string, ext ExtendOp) (string, error) {
	switch ext {
	case ExtendUXTX, ExtendSXTX:
		return v, nil
	}

	var fromTy string
	var extOp string
	switch ext {
	case ExtendUXTB:
		fromTy, extOp = "i8", "zext"
	case ExtendUXTH:
		fromTy, extOp = "i16", "zext"
	case ExtendUXTW:
		fromTy, extOp = "i32", "zext"
	case ExtendSXTB:
		fromTy, extOp = "i8", "sext"
	case ExtendSXTH:
		fromTy, extOp = "i16", "sext"
	case ExtendSXTW:
		fromTy, extOp = "i32", "sext"
	default:
		return "", fmt.Errorf("arm64: unsupported register extension %q", ext)
	}

	tr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v, fromTy)
	ex := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to i64\n", ex, extOp, fromTy, tr)
	return "%" + ex, nil
}

func (c *arm64Ctx) evalFPValue64(op Operand) (string, error) {
	slot, ok := c.fpParams[op.FPOffset]
	var value string
	var err error
	if ok {
		value, err = c.loadFPParameter(slot)
	} else if result, found := c.fpResultSlotByOffset(op.FPOffset); found {
		slot = result
		value, err = c.loadFPResult(slot)
	} else {
		return "", fmt.Errorf("arm64: unsupported FP slot: %s", op.String())
	}
	if err != nil {
		return "", err
	}
	ty := slot.Type

	switch string(ty) {
	case "i64":
		return value, nil
	case "i32", "i16", "i8", "i1":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, value)
		return "%" + t, nil
	case "double":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, value)
		return "%" + t, nil
	case "float":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", t, value)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		return "%" + z, nil
	case "ptr":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, value)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: FP slot %s unsupported arg type %q", op.String(), ty)
	}
}

func (c *arm64Ctx) evalFPAddr64(op Operand) (string, error) {
	p, ok := c.fpResAllocaOff[op.FPOffset]
	result := ok
	if !ok {
		p, ok = c.fpParamAlloca[op.FPOffset]
	}
	if !ok {
		// The ordinary signature does not recover a caller-owned FP address.
		// Missing typed backing is context, never a fabricated zero pointer.
		return "", fmt.Errorf("%w: arm64 FP address %s requires bound typed frame storage", ErrProbeNeedsContext, op.String())
	}
	if result {
		c.markFPResultAddrTaken(op.FPOffset)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
	return "%" + t, nil
}
