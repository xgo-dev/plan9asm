package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strconv"
	"strings"
)

func (c *arm64Ctx) imm64(n int64) string {
	return strconv.FormatInt(n, 10)
}

// addrI64 computes an i64 address from a MemRef.
// If postInc is true, mem.Off is treated as post-increment (address displacement is 0).
func (c *arm64Ctx) addrI64(mem asm.MemRef, postInc bool) (addr string, base asm.Reg, inc int64, err error) {
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
	if c.curPreInc && !postInc && base != "" && off != 0 {
		if err := c.storeReg(base, sum); err != nil {
			return "", "", 0, err
		}
	}
	return sum, base, inc, nil
}

func (c *arm64Ctx) updatePostInc(base asm.Reg, inc int64) error {
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

func (c *arm64Ctx) loadMem(mem asm.MemRef, bits int, postInc bool) (string, error) {
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

func (c *arm64Ctx) storeMem(mem asm.MemRef, bits int, postInc bool, v64 string) error {
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

func validateARM64MemoryIndex(mem asm.MemRef, bits int) error {
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

func (c *arm64Ctx) eval64(op asm.Operand, postInc bool) (string, error) {
	switch op.Kind {
	case asm.OpTLSOffset:
		return asm.EmitTLSOffset(c.b, c.newTmp, op.Sym, 64), nil
	case asm.OpImm:
		return c.imm64(op.Imm), nil
	case asm.OpReg:
		return c.loadReg(op.Reg)
	case asm.OpRegExtend:
		v, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		v, err = c.extendReg64(v, op.Ext)
		if err != nil || op.ShiftOp == "" || op.ShiftAmount == 0 {
			return v, err
		}
		if op.ShiftOp != asm.ShiftLeft || op.ShiftAmount < 0 || op.ShiftAmount > 4 {
			return "", fmt.Errorf("arm64: invalid extended-register shift: %s", op)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", t, v, op.ShiftAmount)
		return "%" + t, nil
	case asm.OpRegShift:
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
		case asm.ShiftRight:
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", t, v, op.ShiftAmount)
		case asm.ShiftLeft:
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", t, v, op.ShiftAmount)
		case asm.ShiftArith:
			fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, %d\n", t, v, op.ShiftAmount)
		case asm.ShiftRotate:
			return c.rotateInt(v, "i64", 64, fmt.Sprintf("%d", op.ShiftAmount)), nil
		default:
			return "", fmt.Errorf("arm64: unsupported shift op %q", op.ShiftOp)
		}
		return "%" + t, nil
	case asm.OpFP:
		return c.evalFPValue64(op)
	case asm.OpFPAddr:
		return c.evalFPAddr64(op)
	case asm.OpMem:
		return c.loadMem(op.Mem, 64, postInc)
	case asm.OpSym:
		sym := strings.TrimSpace(op.Sym)
		addrOnly := strings.HasPrefix(sym, "$")
		if addrOnly {
			sym = strings.TrimSpace(strings.TrimPrefix(sym, "$"))
		}
		if mem, ok := asm.ParseMem(sym); ok {
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
		if addrOnly {
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
			return "%" + t, nil
		}
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case asm.OpIdent:
		// Keep parser/lowering permissive for pseudo operands like NZCV.
		return "0", nil
	default:
		return "", fmt.Errorf("arm64: unsupported operand for i64: %s", op.String())
	}
}

func (c *arm64Ctx) eval32(op asm.Operand) (string, error) {
	truncate := func(value string) string {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, value)
		return "%" + t
	}
	switch op.Kind {
	case asm.OpImm:
		return strconv.FormatUint(uint64(uint32(op.Imm)), 10), nil
	case asm.OpReg:
		v, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		return truncate(v), nil
	case asm.OpRegExtend:
		v, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		var fromType, extend string
		switch op.Ext {
		case asm.ExtendUXTB:
			fromType, extend = "i8", "zext"
		case asm.ExtendUXTH:
			fromType, extend = "i16", "zext"
		case asm.ExtendUXTW, asm.ExtendUXTX:
			fromType = "i32"
		case asm.ExtendSXTB:
			fromType, extend = "i8", "sext"
		case asm.ExtendSXTH:
			fromType, extend = "i16", "sext"
		case asm.ExtendSXTW, asm.ExtendSXTX:
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
			if op.ShiftOp != asm.ShiftLeft || op.ShiftAmount < 0 || op.ShiftAmount > 4 {
				return "", fmt.Errorf("arm64: invalid extended-register shift: %s", op)
			}
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", shifted, value, op.ShiftAmount)
			value = "%" + shifted
		}
		return value, nil
	case asm.OpRegShift:
		if op.ShiftReg != "" || op.ShiftAmount < 0 || op.ShiftAmount > 31 {
			return "", fmt.Errorf("arm64: invalid 32-bit shift: %s", op)
		}
		v, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		v = truncate(v)
		t := c.newTmp()
		switch op.ShiftOp {
		case asm.ShiftLeft:
			fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", t, v, op.ShiftAmount)
		case asm.ShiftRight:
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", t, v, op.ShiftAmount)
		case asm.ShiftArith:
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, %d\n", t, v, op.ShiftAmount)
		case asm.ShiftRotate:
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

func (c *arm64Ctx) extendReg64(v string, ext asm.ExtendOp) (string, error) {
	switch ext {
	case asm.ExtendUXTX, asm.ExtendSXTX:
		return v, nil
	}

	var fromTy string
	var extOp string
	switch ext {
	case asm.ExtendUXTB:
		fromTy, extOp = "i8", "zext"
	case asm.ExtendUXTH:
		fromTy, extOp = "i16", "zext"
	case asm.ExtendUXTW:
		fromTy, extOp = "i32", "zext"
	case asm.ExtendSXTB:
		fromTy, extOp = "i8", "sext"
	case asm.ExtendSXTH:
		fromTy, extOp = "i16", "sext"
	case asm.ExtendSXTW:
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

func (c *arm64Ctx) evalFPValue64(op asm.Operand) (string, error) {
	slot, ok := c.fpParams[op.FPOffset]
	if !ok {
		return "", fmt.Errorf("arm64: unsupported FP param slot: %s", op.String())
	}
	idx := slot.Index
	if idx < 0 || idx >= len(c.sig.Args) {
		return "", fmt.Errorf("arm64: FP slot %s invalid arg index %d", op.String(), idx)
	}
	arg := fmt.Sprintf("%%arg%d", idx)

	ty := slot.Type
	if slot.Field >= 0 {
		aggTy := c.sig.Args[idx]
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", t, aggTy, arg, slot.Field)
		arg = "%" + t
	}

	switch string(ty) {
	case "i64":
		return arg, nil
	case "i32", "i16", "i8", "i1":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, arg)
		return "%" + t, nil
	case "double":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, arg)
		return "%" + t, nil
	case "float":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", t, arg)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		return "%" + z, nil
	case "ptr":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, arg)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: FP slot %s unsupported arg type %q", op.String(), ty)
	}
}

func (c *arm64Ctx) evalFPAddr64(op asm.Operand) (string, error) {
	p, ok := c.fpResAllocaOff[op.FPOffset]
	if !ok {
		return "0", nil
	}
	c.markFPResultAddrTaken(op.FPOffset)
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
	return "%" + t, nil
}
