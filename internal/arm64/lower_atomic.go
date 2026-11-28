package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *arm64Ctx) lowerAtomic(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "LDARW", "LDARB", "LDAR", "LDARH":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpMem || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects mem, reg: %q", op, ins.Raw)
		}
		ty, align := arm64AtomicLoadStoreType(op)
		ptr, err := c.atomicMemPtr(ins.Args[0].Mem)
		if err != nil {
			return true, false, err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s seq_cst, align %d\n", ld, ty, ptr, align)
		v, err := c.atomicExtendToI64("%"+ld, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[1].Reg, v)

	case "STLRW", "STLRB", "STLR":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem {
			return true, false, fmt.Errorf("arm64 %s expects reg, mem: %q", op, ins.Raw)
		}
		ty, align := arm64AtomicLoadStoreType(op)
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		v, err := c.atomicTruncFromI64(src, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store atomic %s %s, ptr %s seq_cst, align %d\n", ty, v, ptr, align)
		return true, false, nil

	case "LDXR", "LDXRB", "LDXRH", "LDXRW", "LDAXR", "LDAXRB", "LDAXRH", "LDAXRW",
		"LDXP", "LDXPW", "LDAXP", "LDAXPW", "STXR", "STXRB", "STXRH", "STXRW",
		"STLXR", "STLXRB", "STLXRH", "STLXRW", "STXP", "STXPW", "STLXP", "STLXPW":
		return true, false, c.lowerExclusive(op, ins)

	case "SWPALB", "SWPALW", "SWPALD":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, mem, dstReg: %q", op, ins.Raw)
		}
		ty, err := arm64AtomicRMWType(op)
		if err != nil {
			return true, false, err
		}
		src64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		src, err := c.atomicTruncFromI64(src64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw xchg ptr %s, %s %s seq_cst\n", old, ptr, ty, src)
		old64, err := c.atomicExtendToI64("%"+old, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[2].Reg, old64)

	case "LDADDALW", "LDADDALD", "LDORALB", "LDORALW", "LDORALD", "LDCLRALB", "LDCLRALW", "LDCLRALD":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, mem, dstReg: %q", op, ins.Raw)
		}
		ty, err := arm64AtomicRMWType(op)
		if err != nil {
			return true, false, err
		}
		src64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		src, err := c.atomicTruncFromI64(src64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}

		rmwo := ""
		arg := src
		switch op {
		case "LDADDALW", "LDADDALD":
			rmwo = "add"
		case "LDORALB", "LDORALW", "LDORALD":
			rmwo = "or"
		case "LDCLRALB", "LDCLRALW", "LDCLRALD":
			rmwo = "and"
			// LDCLR updates memory as: mem = mem & ~src.
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", t, ty, src)
			arg = "%" + t
		}

		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s seq_cst\n", old, rmwo, ptr, ty, arg)
		old64, err := c.atomicExtendToI64("%"+old, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[2].Reg, old64)

	case "CASALW", "CASALD":
		// CASAL{W,D} expectedReg, (ptrReg), newReg
		// The expected register is updated with the loaded memory value.
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects expectedReg, mem, newReg: %q", op, ins.Raw)
		}
		ty := asm.I32
		align := 4
		if op == "CASALD" {
			ty = asm.I64
			align = 8
		}
		exp64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		exp, err := c.atomicTruncFromI64(exp64, ty)
		if err != nil {
			return true, false, err
		}
		new64, err := c.loadReg(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		newv, err := c.atomicTruncFromI64(new64, ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		cx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s seq_cst seq_cst, align %d\n", cx, ptr, ty, exp, ty, newv, align)
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, ty, cx)
		old64, err := c.atomicExtendToI64("%"+old, ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[0].Reg, old64)
	}
	return false, false, nil
}

func (c *arm64Ctx) atomicMemPtr(mem asm.MemRef) (string, error) {
	addr, _, _, err := c.addrI64(mem, false)
	if err != nil {
		return "", err
	}
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
	return "%" + pt, nil
}

func arm64AtomicLoadStoreType(op asm.Op) (asm.LLVMType, int) {
	switch op {
	case "LDARB", "STLRB":
		return asm.I8, 1
	case "LDARH":
		return asm.I16, 2
	case "LDARW", "STLRW":
		return asm.I32, 4
	default:
		return asm.I64, 8
	}
}

func arm64AtomicRMWType(op asm.Op) (asm.LLVMType, error) {
	switch op {
	case "SWPALB", "LDORALB", "LDCLRALB":
		return asm.I8, nil
	case "SWPALW", "LDADDALW", "LDORALW", "LDCLRALW":
		return asm.I32, nil
	case "SWPALD", "LDADDALD", "LDORALD", "LDCLRALD":
		return asm.I64, nil
	default:
		return "", fmt.Errorf("arm64: unsupported atomic rmw op %s", op)
	}
}

func (c *arm64Ctx) atomicTruncFromI64(v64 string, ty asm.LLVMType) (string, error) {
	switch ty {
	case asm.I64:
		return v64, nil
	case asm.I32, asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: unsupported trunc target %s", ty)
	}
}

func (c *arm64Ctx) atomicExtendToI64(v string, ty asm.LLVMType) (string, error) {
	switch ty {
	case asm.I64:
		return v, nil
	case asm.I32, asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("arm64: unsupported extend source %s", ty)
	}
}
