package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strconv"
	"strings"
)

func (c *armCtx) imm32(n int64) string {
	return strconv.FormatInt(n, 10)
}

func (c *armCtx) addrI32(mem asm.MemRef, postInc bool) (addr string, base asm.Reg, inc int64, err error) {
	base = mem.Base
	baseVal, err := c.loadReg(base)
	if err != nil {
		return "", "", 0, err
	}
	off := mem.Off
	if c.curSubOff && off > 0 {
		off = -off
	}
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
	if c.curPreInc && !postInc && base != "" && off != 0 {
		if err := c.storeReg(base, sum); err != nil {
			return "", "", 0, err
		}
	}
	return sum, base, inc, nil
}

func (c *armCtx) updatePostInc(base asm.Reg, inc int64) error {
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

func (c *armCtx) loadMem(mem asm.MemRef, bits int, postInc bool, signed bool) (string, error) {
	addr, base, inc, err := c.addrI32(mem, postInc)
	if err != nil {
		return "", err
	}
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
	if err := c.updatePostInc(base, inc); err != nil {
		return "", err
	}
	return out, nil
}

func (c *armCtx) storeMem(mem asm.MemRef, bits int, postInc bool, v32 string) error {
	addr, base, inc, err := c.addrI32(mem, postInc)
	if err != nil {
		return err
	}
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
	return c.updatePostInc(base, inc)
}

func (c *armCtx) eval32(op asm.Operand, postInc bool) (string, error) {
	switch op.Kind {
	case asm.OpImm:
		if op.ImmRaw != "" {
			return "", fmt.Errorf("arm: unresolved symbolic immediate %q", op.ImmRaw)
		}
		return c.imm32(op.Imm), nil
	case asm.OpReg:
		return c.loadReg(op.Reg)
	case asm.OpRegShift:
		return c.evalShift(op)
	case asm.OpFP:
		return c.evalFPValue32(op)
	case asm.OpFPAddr:
		return c.evalFPAddr32(op)
	case asm.OpMem:
		return c.loadMem(op.Mem, 32, postInc, false)
	case asm.OpSym:
		sym := strings.TrimSpace(op.Sym)
		addrOnly := strings.HasPrefix(sym, "$")
		if addrOnly {
			sym = strings.TrimSpace(strings.TrimPrefix(sym, "$"))
		}
		if mem, ok := asm.ParseMem(sym); ok {
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
		if addrOnly {
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, p)
			return "%" + t, nil
		}
		fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case asm.OpIdent:
		switch strings.ToUpper(op.Ident) {
		case "CPSR":
			return c.readCPSR()
		case "FPCR", "FPSR":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", t, "vmrs $0, fpscr", "=r,~{memory}")
			return "%" + t, nil
		}
		return "0", nil
	default:
		return "", fmt.Errorf("arm: unsupported operand for i32: %s", op.String())
	}
}

// armImmRot mirrors Go's cmd/internal/obj/arm/asm5.go immrot(v): returns the
// smallest 4-bit even rotate (0..15) encoding v as an ARMv7 modified immediate,
// or ok=false if v cannot be represented in imm12.
func armImmRot(v uint32) (rot int, ok bool) {
	for i := 0; i < 16; i++ {
		if v&^0xff == 0 {
			return i, true
		}
		v = v<<2 | v>>30
	}
	return 0, false
}

// armImmLogicalCarry returns the constant ARMv7 ARMExpandImm_C shifter carry-out
// ("true" or "false") when Go's ARM assembler encodes op $imm as a single
// rotated-immediate instruction with rot != 0. When rot == 0 or Go synthesizes
// the constant into R11 and executes a register instruction, C is unchanged
// (ok == false). For AND, Go rewrites C_NCON ($v where immrot(^v)!=0) to
// BIC $^v, so carry comes from ^v's rotated encoding.
func armImmLogicalCarry(op string, imm int64) (string, bool) {
	u := uint32(imm)
	if rot, ok := armImmRot(u); ok {
		if rot == 0 {
			return "", false
		}
		if (u & (1 << 31)) != 0 {
			return "true", true
		}
		return "false", true
	}
	if op == "AND" {
		inv := ^u
		if rot, ok := armImmRot(inv); ok {
			if rot == 0 {
				return "", false
			}
			if (inv & (1 << 31)) != 0 {
				return "true", true
			}
			return "false", true
		}
	}
	return "", false
}

func (c *armCtx) evalShift(op asm.Operand) (string, error) {
	out, _, err := c.evalShiftWithCarry(op, false)
	return out, err
}

func (c *armCtx) evalShiftWithCarry(op asm.Operand, wantCarry bool) (string, string, error) {
	base, err := c.loadReg(op.Reg)
	if err != nil {
		return "", "", err
	}
	var sh string
	if op.ShiftReg != "" {
		sh, err = c.loadReg(op.ShiftReg)
		if err != nil {
			return "", "", err
		}
	} else {
		sh = c.imm32(op.ShiftAmount)
	}
	return c.evalARMShift(op.ShiftOp, base, sh, wantCarry)
}

// evalARMShift lowers ARMv7 barrel-shift/rotate value and optional exact
// shifter carry-out (ARMv7-A/R ARM §A2.2.1 Shift_C). Counts are masked to 8
// bits; shift by 0 preserves the current C flag.
func (c *armCtx) evalARMShift(shiftOp asm.ShiftOp, src, amt string, wantCarry bool) (string, string, error) {
	amt8 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 255\n", amt8, amt)
	isZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 0\n", isZero, amt8)

	var out string
	var carryOut string
	switch shiftOp {
	case asm.ShiftLeft, asm.ShiftRight, asm.ShiftArith:
		llvmOp := "shl"
		if shiftOp == asm.ShiftRight {
			llvmOp = "lshr"
		} else if shiftOp == asm.ShiftArith {
			llvmOp = "ashr"
		}
		big := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp uge i32 %%%s, 32\n", big, amt8)
		clamped := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 31, i32 %%%s\n", clamped, big, amt8)
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %%%s\n", shifted, llvmOp, src, clamped)
		if shiftOp == asm.ShiftArith {
			sign := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %s, 31\n", sign, src)
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %%%s\n", sel, big, sign, shifted)
			out = "%" + sel
		} else {
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 0, i32 %%%s\n", sel, big, shifted)
			out = "%" + sel
		}
		if wantCarry {
			oldC := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", oldC, c.flagsCSlot)
			oob := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", oob, isZero, big)
			rawPos := c.newTmp()
			if shiftOp == asm.ShiftLeft {
				fmt.Fprintf(c.b, "  %%%s = sub i32 32, %%%s\n", rawPos, amt8)
			} else {
				fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", rawPos, amt8)
			}
			safePos := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 0, i32 %%%s\n", safePos, oob, rawPos)
			bitW := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %%%s\n", bitW, src, safePos)
			cInRange := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i1\n", cInRange, bitW)
			var cBig string
			switch shiftOp {
			case asm.ShiftLeft:
				isEq32 := c.newTmp()
				bit0 := c.newTmp()
				sel32 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 32\n", isEq32, amt8)
				fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i1\n", bit0, src)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %%%s, i1 false\n", sel32, isEq32, bit0)
				cBig = "%" + sel32
			case asm.ShiftRight:
				isEq32 := c.newTmp()
				bit31 := c.newTmp()
				sel32 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 32\n", isEq32, amt8)
				fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", bit31, src)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %%%s, i1 false\n", sel32, isEq32, bit31)
				cBig = "%" + sel32
			case asm.ShiftArith:
				bit31 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", bit31, src)
				cBig = "%" + bit31
			}
			cNonZero := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %s, i1 %%%s\n", cNonZero, big, cBig, cInRange)
			cFinal := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %%%s, i1 %%%s\n", cFinal, isZero, oldC, cNonZero)
			carryOut = "%" + cFinal
		}
	case asm.ShiftRotate:
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %%%s)\n", rot, src, src, amt8)
		out = "%" + rot
		if wantCarry {
			oldC := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", oldC, c.flagsCSlot)
			msb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", msb, out)
			cFinal := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %%%s, i1 %%%s\n", cFinal, isZero, oldC, msb)
			carryOut = "%" + cFinal
		}
	default:
		return "", "", fmt.Errorf("arm: unsupported shift op %q", shiftOp)
	}
	return out, carryOut, nil
}

func (c *armCtx) evalFPValue32(op asm.Operand) (string, error) {
	slot, ok := c.fpParams[op.FPOffset]
	if !ok {
		for base, candidate := range c.fpParams {
			if candidate.Type != asm.I64 || op.FPOffset != base+4 {
				continue
			}
			p := c.fpParamAlloca[base]
			if p == "" {
				return "", fmt.Errorf("arm: missing FP param alloca for +%d(FP)", base)
			}
			full := c.newTmp()
			hi := c.newTmp()
			word := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", full, p)
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hi, full)
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
	} else if slot.Field >= 0 {
		aggTy := c.sig.Args[slot.Index]
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", t, aggTy, arg, slot.Field)
		arg = "%" + t
	}
	switch slot.Type {
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, arg)
		return "%" + t, nil
	case asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", t, arg)
		return "%" + t, nil
	case asm.I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i32\n", t, arg)
		return "%" + t, nil
	case asm.I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", t, arg)
		return "%" + t, nil
	case asm.I32:
		return arg, nil
	case asm.LLVMType("float"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", t, arg)
		return "%" + t, nil
	case asm.I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, arg)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm: unsupported FP slot type %q", slot.Type)
	}
}

func (c *armCtx) evalFPValue64(op asm.Operand) (string, error) {
	slot, ok := c.fpParams[op.FPOffset]
	if !ok {
		return "", fmt.Errorf("arm: unsupported 64-bit FP slot: %s", op.String())
	}
	p := c.fpParamAlloca[op.FPOffset]
	if p == "" {
		return "", fmt.Errorf("arm: missing FP param alloca for +%d(FP)", op.FPOffset)
	}
	ld := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", ld, slot.Type, p)
	switch slot.Type {
	case asm.I64:
		return "%" + ld, nil
	case asm.LLVMType("double"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %%%s to i64\n", t, ld)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm: unsupported 64-bit FP slot type %q", slot.Type)
	}
}

func (c *armCtx) evalFPAddr32(op asm.Operand) (string, error) {
	if slot, ok := c.fpResAllocaOff[op.FPOffset]; ok {
		c.markFPResultAddrTaken(op.FPOffset)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, slot)
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
	return "", fmt.Errorf("arm: unsupported FP addr slot: %s", op.String())
}
