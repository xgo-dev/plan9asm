package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func armNextReg(r Reg) (Reg, error) {
	s := strings.ToUpper(string(r))
	if !strings.HasPrefix(s, "R") {
		return "", fmt.Errorf("arm: expected integer reg, got %s", r)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "R"))
	if err != nil {
		return "", err
	}
	if n < 0 || n >= 15 {
		return "", fmt.Errorf("arm: cannot compute next reg for %s", r)
	}
	return Reg(fmt.Sprintf("R%d", n+1)), nil
}

func (c *armCtx) atomicMemPtr(mem MemRef) (string, error) {
	addr, _, _, err := c.addrI32(mem, false)
	if err != nil {
		return "", err
	}
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pt, addr)
	return "%" + pt, nil
}

func armAtomicType(op string) (LLVMType, int, error) {
	switch op {
	case "LDREXB", "STREXB":
		return I8, 1, nil
	case "LDREX", "STREX":
		return I32, 4, nil
	case "LDREXD", "STREXD":
		return I64, 8, nil
	default:
		return "", 0, fmt.Errorf("arm: unsupported atomic op %s", op)
	}
}

func (c *armCtx) atomicExtendToI32(v string, ty LLVMType) (string, error) {
	switch ty {
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i32\n", t, v)
		return "%" + t, nil
	case I32:
		return v, nil
	default:
		return "", fmt.Errorf("arm: unsupported atomic extend type %s", ty)
	}
}

func (c *armCtx) atomicTruncFromI32(v string, ty LLVMType) (string, error) {
	switch ty {
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", t, v)
		return "%" + t, nil
	case I32:
		return v, nil
	default:
		return "", fmt.Errorf("arm: unsupported atomic trunc type %s", ty)
	}
}

func (c *armCtx) lowerAtomic(op string, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "LDREX", "LDREXB":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm %s expects mem, reg: %q", op, ins.Raw)
		}
		ty, align, err := armAtomicType(op)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[0].Mem)
		if err != nil {
			return true, false, err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s seq_cst, align %d\n", ld, ty, ptr, align)
		v, err := c.atomicExtendToI32("%"+ld, ty)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.exclusiveValidSlot)
		fmt.Fprintf(c.b, "  store ptr %s, ptr %s\n", ptr, c.exclusivePtrSlot)
		fmt.Fprintf(c.b, "  store i8 %d, ptr %s\n", align, c.exclusiveSizeSlot)
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", c.zextI32ToI64(v), c.exclusiveValueSlot)
		return true, false, c.storeReg(ins.Args[1].Reg, v)

	case "LDREXD":
		var mem Operand
		var loReg, hiReg Reg
		switch {
		case len(ins.Args) == 2 && ins.Args[0].Kind == OpMem && ins.Args[1].Kind == OpReg:
			mem, loReg = ins.Args[0], ins.Args[1].Reg
		case len(ins.Args) == 3 && ins.Args[0].Kind == OpMem && ins.Args[1].Kind == OpReg && ins.Args[2].Kind == OpReg:
			// x/arch's raw ARM syntax prints the implicit pair explicitly as
			// mem, regHi, regLo; Go source syntax prints mem, regLo.
			mem, hiReg, loReg = ins.Args[0], ins.Args[1].Reg, ins.Args[2].Reg
		default:
			return true, false, fmt.Errorf("arm LDREXD expects mem, regLo (or decoded mem, regHi, regLo): %q", ins.Raw)
		}
		if hiReg == "" {
			var err error
			hiReg, err = armNextReg(loReg)
			if err != nil {
				return true, false, err
			}
		} else {
			wantHi, err := armNextReg(loReg)
			if err != nil || hiReg != wantHi {
				return true, false, fmt.Errorf("arm LDREXD register pair must be consecutive: %q", ins.Raw)
			}
		}
		if loReg == "" {
			return true, false, fmt.Errorf("arm LDREXD missing low register: %q", ins.Raw)
		}
		ptr, err := c.atomicMemPtr(mem.Mem)
		if err != nil {
			return true, false, err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic i64, ptr %s seq_cst, align 8\n", ld, ptr)
		lo := c.newTmp()
		hiShift := c.newTmp()
		hi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo, ld)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiShift, ld)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiShift)
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.exclusiveValidSlot)
		fmt.Fprintf(c.b, "  store ptr %s, ptr %s\n", ptr, c.exclusivePtrSlot)
		fmt.Fprintf(c.b, "  store i8 8, ptr %s\n", c.exclusiveSizeSlot)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", ld, c.exclusiveValueSlot)
		if err := c.storeReg(loReg, "%"+lo); err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(hiReg, "%"+hi)

	case "STREX", "STREXB":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm %s expects srcReg, mem, statusReg: %q", op, ins.Raw)
		}
		ty, align, err := armAtomicType(op)
		if err != nil {
			return true, false, err
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		newv, err := c.atomicTruncFromI32(src, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		status, err := c.lowerAtomicExclusiveStore(ty, align, ptr, newv)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[2].Reg, status)

	case "STREXD":
		var loReg, hiReg, statusReg Reg
		var mem Operand
		switch {
		case len(ins.Args) == 3 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpMem && ins.Args[2].Kind == OpReg:
			loReg, mem, statusReg = ins.Args[0].Reg, ins.Args[1], ins.Args[2].Reg
		case len(ins.Args) == 4 && ins.Args[0].Kind == OpMem && ins.Args[1].Kind == OpReg && ins.Args[2].Kind == OpReg && ins.Args[3].Kind == OpReg:
			// x/arch's raw ARM syntax prints mem, regHi, regLo, status.
			mem, hiReg, loReg, statusReg = ins.Args[0], ins.Args[1].Reg, ins.Args[2].Reg, ins.Args[3].Reg
		default:
			return true, false, fmt.Errorf("arm STREXD expects srcLoReg, mem, statusReg (or decoded mem, regHi, regLo, statusReg): %q", ins.Raw)
		}
		var err error
		if hiReg == "" {
			hiReg, err = armNextReg(loReg)
		} else {
			wantHi, pairErr := armNextReg(loReg)
			if pairErr != nil || hiReg != wantHi {
				err = fmt.Errorf("arm STREXD register pair must be consecutive: %q", ins.Raw)
			}
		}
		if err != nil {
			return true, false, err
		}
		lo, err := c.loadReg(loReg)
		if err != nil {
			return true, false, err
		}
		hi, err := c.loadReg(hiReg)
		if err != nil {
			return true, false, err
		}
		lo64 := c.zextI32ToI64(lo)
		hi64 := c.zextI32ToI64(hi)
		hiShift := c.newTmp()
		new64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 32\n", hiShift, hi64)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", new64, hiShift, lo64)
		ptr, err := c.atomicMemPtr(mem.Mem)
		if err != nil {
			return true, false, err
		}
		status, err := c.lowerAtomicExclusiveStore(I64, 8, ptr, "%"+new64)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(statusReg, status)
	}
	return false, false, nil
}

func (c *armCtx) lowerAtomicExclusiveStore(ty LLVMType, align int, ptr string, newv string) (string, error) {
	loadedValid := c.newTmp()
	loadedPtr := c.newTmp()
	ptrMatch := c.newTmp()
	loadedSize := c.newTmp()
	sizeMatch := c.newTmp()
	precond := c.newTmp()
	canTry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", loadedValid, c.exclusiveValidSlot)
	fmt.Fprintf(c.b, "  %%%s = load ptr, ptr %s\n", loadedPtr, c.exclusivePtrSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp eq ptr %%%s, %s\n", ptrMatch, loadedPtr, ptr)
	fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s\n", loadedSize, c.exclusiveSizeSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, %d\n", sizeMatch, loadedSize, align)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", precond, loadedValid, ptrMatch)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", canTry, precond, sizeMatch)

	id := c.newTmp()
	tryLabel := armLLVMBlockName("strex_try_" + id)
	failLabel := armLLVMBlockName("strex_fail_" + id)
	mergeLabel := armLLVMBlockName("strex_merge_" + id)
	fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n", canTry, tryLabel, failLabel)

	fmt.Fprintf(c.b, "\n%s:\n", tryLabel)
	expected64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", expected64, c.exclusiveValueSlot)
	expected := ""
	switch ty {
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", t, expected64)
		expected = "%" + t
	case I32:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", t, expected64)
		expected = "%" + t
	case I64:
		expected = "%" + expected64
	default:
		return "", fmt.Errorf("arm: unsupported atomic expected type %s", ty)
	}
	cx := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s seq_cst seq_cst, align %d\n", cx, ptr, ty, expected, ty, newv, align)
	ok := c.newTmp()
	failI1 := c.newTmp()
	tryStatus := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 1\n", ok, ty, cx)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", failI1, ok)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", tryStatus, failI1)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

	fmt.Fprintf(c.b, "\n%s:\n", failLabel)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

	fmt.Fprintf(c.b, "\n%s:\n", mergeLabel)
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = phi i32 [ %%%s, %%%s ], [ 1, %%%s ]\n", status, tryStatus, tryLabel, failLabel)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
	return "%" + status, nil
}
