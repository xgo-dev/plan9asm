package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

type arm64LSEKind uint8

const (
	lseNone arm64LSEKind = iota
	lseAdd
	lseClr
	lseEor
	lseOr
	lseSMax
	lseSMin
	lseUMax
	lseUMin
	lseSwp
	lseCas
	lseCasp
)

type arm64LSEDesc struct {
	kind  arm64LSEKind
	order string // monotonic, acquire, release, acq_rel
	ty    asm.LLVMType
	align int
	bits  int
}

// parseARM64LSEOp decodes the entire AArch64 LSE atomic opcode matrix
// (LD{ADD,CLR,EOR,OR,SMAX,SMIN,UMAX,UMIN}, SWP, CAS, CASP x {"",A,L,AL} x {B,H,W,D})
// into a structured descriptor without hand-writing 160+ case clauses.
func parseARM64LSEOp(op asm.Op) (arm64LSEDesc, bool) {
	s := string(op)
	var kind arm64LSEKind
	var rest string
	switch {
	case strings.HasPrefix(s, "LDADD"):
		kind, rest = lseAdd, strings.TrimPrefix(s, "LDADD")
	case strings.HasPrefix(s, "LDCLR"):
		kind, rest = lseClr, strings.TrimPrefix(s, "LDCLR")
	case strings.HasPrefix(s, "LDEOR"):
		kind, rest = lseEor, strings.TrimPrefix(s, "LDEOR")
	case strings.HasPrefix(s, "LDOR"):
		kind, rest = lseOr, strings.TrimPrefix(s, "LDOR")
	case strings.HasPrefix(s, "LDSMAX"):
		kind, rest = lseSMax, strings.TrimPrefix(s, "LDSMAX")
	case strings.HasPrefix(s, "LDSMIN"):
		kind, rest = lseSMin, strings.TrimPrefix(s, "LDSMIN")
	case strings.HasPrefix(s, "LDUMAX"):
		kind, rest = lseUMax, strings.TrimPrefix(s, "LDUMAX")
	case strings.HasPrefix(s, "LDUMIN"):
		kind, rest = lseUMin, strings.TrimPrefix(s, "LDUMIN")
	case strings.HasPrefix(s, "SWP"):
		kind, rest = lseSwp, strings.TrimPrefix(s, "SWP")
	case strings.HasPrefix(s, "CASP"):
		kind, rest = lseCasp, strings.TrimPrefix(s, "CASP")
	case strings.HasPrefix(s, "CAS"):
		kind, rest = lseCas, strings.TrimPrefix(s, "CAS")
	default:
		return arm64LSEDesc{}, false
	}
	if len(rest) == 0 {
		return arm64LSEDesc{}, false
	}
	widthChar := rest[len(rest)-1]
	ordStr := rest[:len(rest)-1]
	order := ""
	switch ordStr {
	case "":
		order = "monotonic"
	case "A":
		order = "acquire"
	case "L":
		order = "release"
	case "AL":
		order = "acq_rel"
	default:
		return arm64LSEDesc{}, false
	}
	if kind == lseCasp {
		switch widthChar {
		case 'W':
			return arm64LSEDesc{kind: kind, order: order, ty: asm.I64, align: 8, bits: 32}, true
		case 'D':
			return arm64LSEDesc{kind: kind, order: order, ty: asm.LLVMType("i128"), align: 16, bits: 64}, true
		default:
			return arm64LSEDesc{}, false
		}
	}
	switch widthChar {
	case 'B':
		return arm64LSEDesc{kind: kind, order: order, ty: asm.I8, align: 1, bits: 8}, true
	case 'H':
		return arm64LSEDesc{kind: kind, order: order, ty: asm.I16, align: 2, bits: 16}, true
	case 'W':
		return arm64LSEDesc{kind: kind, order: order, ty: asm.I32, align: 4, bits: 32}, true
	case 'D':
		return arm64LSEDesc{kind: kind, order: order, ty: asm.I64, align: 8, bits: 64}, true
	default:
		return arm64LSEDesc{}, false
	}
}

func (c *arm64Ctx) lowerAtomicDeclarative(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	// Exclusive / acquire-release halfword & non-ordered exclusives & pairs.
	switch op {
	case "LDARH", "LDXR", "LDXRB", "LDXRH", "LDXRW", "LDAXRH":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpMem || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects mem, reg: %q", op, ins.Raw)
		}
		ty, align, size := arm64ExclLoadInfo(op)
		ptr, err := c.atomicMemPtr(ins.Args[0].Mem)
		if err != nil {
			return true, false, err
		}
		ord := "acquire"
		if strings.HasPrefix(string(op), "LDXR") {
			ord = "monotonic"
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s %s, align %d\n", ld, ty, ptr, ord, align)
		v, err := c.atomicExtendToI64("%"+ld, ty)
		if err != nil {
			return true, false, err
		}
		if strings.Contains(string(op), "XR") {
			fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.exclusiveValidSlot)
			fmt.Fprintf(c.b, "  store ptr %s, ptr %s\n", ptr, c.exclusivePtrSlot)
			fmt.Fprintf(c.b, "  store i8 %d, ptr %s\n", size, c.exclusiveSizeSlot)
			fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, c.exclusiveValueSlot)
		}
		return true, false, c.storeReg(ins.Args[1].Reg, v)

	case "STLRH":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem {
			return true, false, fmt.Errorf("arm64 STLRH expects reg, mem: %q", ins.Raw)
		}
		src, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		v, err := c.atomicTruncFromI64(src, asm.I16)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store atomic i16 %s, ptr %s release, align 2\n", v, ptr)
		return true, false, nil

	case "STXR", "STXRB", "STXRH", "STXRW", "STLXRH":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, mem, statusReg: %q", op, ins.Raw)
		}
		ty, align, size := arm64ExclLoadInfo(op)
		return true, false, c.emitStoreExclusive(ty, align, size, ins)

	case "LDXP", "LDXPW", "LDAXP", "LDAXPW":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpMem || ins.Args[1].Kind != asm.OpRegList || len(ins.Args[1].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects mem, (r1, r2): %q", op, ins.Raw)
		}
		word := strings.HasSuffix(string(op), "W")
		ptr, err := c.atomicMemPtr(ins.Args[0].Mem)
		if err != nil {
			return true, false, err
		}
		ord := "monotonic"
		if strings.HasPrefix(string(op), "LDA") {
			ord = "acquire"
		}
		elemTy, step, align := "i64", 8, 8
		if word {
			elemTy, step, align = "i32", 4, 4
		}
		v0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %s %s, align %d\n", v0, elemTy, ptr, ord, align)
		p1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", p1, ptr, step)
		v1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load atomic %s, ptr %%%s %s, align %d\n", v1, elemTy, p1, ord, align)
		out0, out1 := "%"+v0, "%"+v1
		if word {
			z0, z1 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z0, v0)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z1, v1)
			out0, out1 = "%"+z0, "%"+z1
		}
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.exclusiveValidSlot)
		fmt.Fprintf(c.b, "  store ptr %s, ptr %s\n", ptr, c.exclusivePtrSlot)
		fmt.Fprintf(c.b, "  store i8 %d, ptr %s\n", step*2, c.exclusiveSizeSlot)
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", out0, c.exclusiveValueSlot)
		if err := c.storeReg(ins.Args[1].RegList[0], out0); err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[1].RegList[1], out1)

	case "STXP", "STXPW", "STLXP", "STLXPW":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpRegList || len(ins.Args[0].RegList) != 2 || ins.Args[1].Kind != asm.OpMem || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects (r1, r2), mem, statusReg: %q", op, ins.Raw)
		}
		word := strings.HasSuffix(string(op), "W")
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		r0, err := c.loadReg(ins.Args[0].RegList[0])
		if err != nil {
			return true, false, err
		}
		r1, err := c.loadReg(ins.Args[0].RegList[1])
		if err != nil {
			return true, false, err
		}
		ord := "monotonic"
		if strings.HasPrefix(string(op), "STL") {
			ord = "release"
		}
		elemTy, step, align := "i64", 8, 8
		v0, v1 := r0, r1
		if word {
			elemTy, step, align = "i32", 4, 4
			t0, t1 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t0, r0)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t1, r1)
			v0, v1 = "%"+t0, "%"+t1
		}
		valid := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", valid, c.exclusiveValidSlot)
		id := c.newTmp()
		tryLbl := asm.LLVMBlockName("stxp_try_" + id)
		failLbl := asm.LLVMBlockName("stxp_fail_" + id)
		doneLbl := asm.LLVMBlockName("stxp_done_" + id)
		fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n", valid, tryLbl, failLbl)
		fmt.Fprintf(c.b, "\n%s:\n", tryLbl)
		fmt.Fprintf(c.b, "  store atomic %s %s, ptr %s %s, align %d\n", elemTy, v0, ptr, ord, align)
		p1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", p1, ptr, step)
		fmt.Fprintf(c.b, "  store atomic %s %s, ptr %%%s %s, align %d\n", elemTy, v1, p1, ord, align)
		fmt.Fprintf(c.b, "  br label %%%s\n", doneLbl)
		fmt.Fprintf(c.b, "\n%s:\n", failLbl)
		fmt.Fprintf(c.b, "  br label %%%s\n", doneLbl)
		fmt.Fprintf(c.b, "\n%s:\n", doneLbl)
		st := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = phi i64 [ 0, %%%s ], [ 1, %%%s ]\n", st, tryLbl, failLbl)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
		return true, false, c.storeReg(ins.Args[2].Reg, "%"+st)
	}

	desc, found := parseARM64LSEOp(op)
	if !found {
		return false, false, nil
	}
	switch desc.kind {
	case lseCas:
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects expectedReg, mem, newReg: %q", op, ins.Raw)
		}
		exp64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		exp, err := c.atomicTruncFromI64(exp64, desc.ty)
		if err != nil {
			return true, false, err
		}
		new64, err := c.loadReg(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		newv, err := c.atomicTruncFromI64(new64, desc.ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		failOrd := desc.order
		if failOrd == "release" {
			failOrd = "monotonic"
		} else if failOrd == "acq_rel" {
			failOrd = "acquire"
		}
		cx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n", cx, ptr, desc.ty, exp, desc.ty, newv, desc.order, failOrd, desc.align)
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, desc.ty, cx)
		old64, err := c.atomicExtendToI64("%"+old, desc.ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[0].Reg, old64)

	case lseCasp:
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpRegList || len(ins.Args[0].RegList) != 2 || ins.Args[1].Kind != asm.OpMem || ins.Args[2].Kind != asm.OpRegList || len(ins.Args[2].RegList) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects (expLo,expHi), mem, (newLo,newHi): %q", op, ins.Raw)
		}
		packPair := func(regs []asm.Reg) (string, error) {
			lo, err := c.loadReg(regs[0])
			if err != nil {
				return "", err
			}
			hi, err := c.loadReg(regs[1])
			if err != nil {
				return "", err
			}
			if desc.bits == 32 {
				lo32, hi32, lo64, hi64, hiSh, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", lo32, lo)
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", hi32, hi)
				fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", lo64, lo32)
				fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", hi64, hi32)
				fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", hiSh, hi64)
				fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", out, hiSh, lo64)
				return "%" + out, nil
			}
			lo128, hi128, hiSh, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", lo128, lo)
			fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", hi128, hi)
			fmt.Fprintf(c.b, "  %%%s = shl i128 %%%s, 64\n", hiSh, hi128)
			fmt.Fprintf(c.b, "  %%%s = or i128 %%%s, %%%s\n", out, hiSh, lo128)
			return "%" + out, nil
		}
		expVal, err := packPair(ins.Args[0].RegList)
		if err != nil {
			return true, false, err
		}
		newVal, err := packPair(ins.Args[2].RegList)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		failOrd := desc.order
		if failOrd == "release" {
			failOrd = "monotonic"
		} else if failOrd == "acq_rel" {
			failOrd = "acquire"
		}
		cx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s %s %s, align %d\n", cx, ptr, desc.ty, expVal, desc.ty, newVal, desc.order, failOrd, desc.align)
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 0\n", old, desc.ty, cx)
		if desc.bits == 32 {
			lo32, hiSh, hi32, lo64, hi64 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo32, old)
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiSh, old)
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi32, hiSh)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", lo64, lo32)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", hi64, hi32)
			if err := c.storeReg(ins.Args[0].RegList[0], "%"+lo64); err != nil {
				return true, false, err
			}
			return true, false, c.storeReg(ins.Args[0].RegList[1], "%"+hi64)
		}
		lo64, hiSh, hi64 := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", lo64, old)
		fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", hiSh, old)
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", hi64, hiSh)
		if err := c.storeReg(ins.Args[0].RegList[0], "%"+lo64); err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[0].RegList[1], "%"+hi64)

	default:
		// LD{ADD,CLR,EOR,OR,SMAX,SMIN,UMAX,UMIN} and SWP: srcReg, (ptr)[, dstReg]
		if (len(ins.Args) != 2 && len(ins.Args) != 3) || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpMem {
			return true, false, fmt.Errorf("arm64 %s expects srcReg, mem[, dstReg]: %q", op, ins.Raw)
		}
		if len(ins.Args) == 3 && ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s dst must be reg: %q", op, ins.Raw)
		}
		src64, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		src, err := c.atomicTruncFromI64(src64, desc.ty)
		if err != nil {
			return true, false, err
		}
		ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		rmwOp := ""
		arg := src
		switch desc.kind {
		case lseAdd:
			rmwOp = "add"
		case lseClr:
			rmwOp = "and"
			inv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inv, desc.ty, src)
			arg = "%" + inv
		case lseEor:
			rmwOp = "xor"
		case lseOr:
			rmwOp = "or"
		case lseSMax:
			rmwOp = "max"
		case lseSMin:
			rmwOp = "min"
		case lseUMax:
			rmwOp = "umax"
		case lseUMin:
			rmwOp = "umin"
		case lseSwp:
			rmwOp = "xchg"
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = atomicrmw %s ptr %s, %s %s %s\n", old, rmwOp, ptr, desc.ty, arg, desc.order)
		if len(ins.Args) == 2 {
			return true, false, nil
		}
		old64, err := c.atomicExtendToI64("%"+old, desc.ty)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeReg(ins.Args[2].Reg, old64)
	}
}

func arm64ExclLoadInfo(op asm.Op) (asm.LLVMType, int, int) {
	s := string(op)
	switch s[len(s)-1] {
	case 'B':
		return asm.I8, 1, 1
	case 'H':
		return asm.I16, 2, 2
	case 'W':
		return asm.I32, 4, 4
	default:
		return asm.I64, 8, 8
	}
}

func (c *arm64Ctx) emitStoreExclusive(ty asm.LLVMType, align, size int, ins asm.Instr) error {
	src, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	newv, err := c.atomicTruncFromI64(src, ty)
	if err != nil {
		return err
	}
	ptr, err := c.atomicMemPtr(ins.Args[1].Mem)
	if err != nil {
		return err
	}
	loadedValid := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", loadedValid, c.exclusiveValidSlot)
	loadedPtr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load ptr, ptr %s\n", loadedPtr, c.exclusivePtrSlot)
	ptrMatch := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq ptr %%%s, %s\n", ptrMatch, loadedPtr, ptr)
	loadedSize := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s\n", loadedSize, c.exclusiveSizeSlot)
	sizeMatch := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, %d\n", sizeMatch, loadedSize, size)
	precond := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", precond, loadedValid, ptrMatch)
	canTry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", canTry, precond, sizeMatch)

	id := c.newTmp()
	tryLabel := asm.LLVMBlockName("stxr_try_" + id)
	failLabel := asm.LLVMBlockName("stxr_fail_" + id)
	mergeLabel := asm.LLVMBlockName("stxr_merge_" + id)
	fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n", canTry, tryLabel, failLabel)

	fmt.Fprintf(c.b, "\n%s:\n", tryLabel)
	expected64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", expected64, c.exclusiveValueSlot)
	expected, err := c.atomicTruncFromI64("%"+expected64, ty)
	if err != nil {
		return err
	}
	cx := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %s, %s %s, %s %s seq_cst seq_cst, align %d\n", cx, ptr, ty, expected, ty, newv, align)
	okv := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {%s, i1} %%%s, 1\n", okv, ty, cx)
	failI1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", failI1, okv)
	tryStatus := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", tryStatus, failI1)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

	fmt.Fprintf(c.b, "\n%s:\n", failLabel)
	fmt.Fprintf(c.b, "  br label %%%s\n", mergeLabel)

	fmt.Fprintf(c.b, "\n%s:\n", mergeLabel)
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = phi i64 [ %%%s, %%%s ], [ 1, %%%s ]\n", status, tryStatus, tryLabel, failLabel)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
	return c.storeReg(ins.Args[2].Reg, "%"+status)
}
