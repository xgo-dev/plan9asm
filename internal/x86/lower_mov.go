package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *amd64Ctx) lowerMov(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "MOVQ", "MOVD", "MOVL", "MOVQL", "MOVLQZX", "MOVLQSX", "MOVBQZX", "MOVBLZX", "MOVB", "MOVW", "MOVWLZX", "MOVWQZX", "MOVWQSX", "CMOVQLT":
		// ok
	default:
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("amd64 %s expects 2 operands: %q", op, ins.Raw)
	}
	src, dst := ins.Args[0], ins.Args[1]
	if readsCallerPC(ins, c.goarch) {
		if !matchesX86Target(c.goarch, c.targetTriple) {
			return true, false, fmt.Errorf("%w: x86 caller return PC requires a matching explicit target", asm.ErrProbeNeedsContext)
		}
		ptr, word := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call ptr @llvm.returnaddress(i32 0)\n", ptr)
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", word, ptr)
		return true, false, c.storeReg(dst.Reg, "%"+word)
	}
	zeroExtendSmallDst := false
	if op == "MOVLQZX" || op == "MOVQL" {
		op = "MOVL"
	}
	if op == "MOVD" {
		op = "MOVQ"
	}
	if op == "MOVBQZX" || op == "MOVBLZX" {
		op = "MOVB"
		zeroExtendSmallDst = true
	}
	if op == "MOVWQZX" || op == "MOVWLZX" {
		op = "MOVW"
		zeroExtendSmallDst = true
	}
	if op == "MOVLQSX" || op == "MOVWQSX" {
		// Sign-extend i32/i16 source to i64 destination register.
		if dst.Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 %s expects dst reg: %q", op, ins.Raw)
		}
		srcTy := asm.I32
		if op == "MOVWQSX" {
			srcTy = asm.I16
		}
		var sv string
		switch src.Kind {
		case asm.OpImm:
			switch srcTy {
			case asm.I16:
				sv = fmt.Sprintf("%d", int16(src.Imm))
			default:
				sv = fmt.Sprintf("%d", int32(src.Imm))
			}
		case asm.OpReg, asm.OpFP:
			v64, err := c.evalI64(src)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v64, srcTy)
			sv = "%" + tr
		case asm.OpMem:
			p, ptrType, err := c.ptrFromMem(src.Mem)
			if err != nil {
				return true, false, err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", ld, srcTy, ptrType, p)
			sv = "%" + ld
		case asm.OpSym:
			p, err := c.ptrFromSB(src.Sym)
			if err != nil {
				return true, false, err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, srcTy, p)
			sv = "%" + ld
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		}
		se := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to i64\n", se, srcTy, sv)
		return true, false, c.storeReg(dst.Reg, "%"+se)
	}

	// Vector moves are handled in lowerVec.
	if dst.Kind == asm.OpReg {
		if _, ok := amd64ParseXReg(dst.Reg); ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(dst.Reg); ok {
			return false, false, nil
		}
	}
	if src.Kind == asm.OpReg {
		if _, ok := amd64ParseXReg(src.Reg); ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(src.Reg); ok {
			return false, false, nil
		}
	}

	switch op {
	case "CMOVQLT":
		// CMOVQLT src, dstReg
		if dst.Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 CMOVQLT expects src, reg: %q", ins.Raw)
		}
		cond, _ := c.x86CondValue("LT")
		sv, err := c.evalI64(src)
		if err != nil {
			return true, false, err
		}
		dv, err := c.loadReg(dst.Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", t, cond, sv, dv)
		return true, false, c.storeReg(dst.Reg, "%"+t)

	case "MOVB", "MOVW":
		// MOVB/MOVW src, dst
		widthTy := asm.I8
		if op == "MOVW" {
			widthTy = asm.I16
		}
		var small string
		switch src.Kind {
		case asm.OpImm:
			small = fmt.Sprintf("%d", src.Imm)
		case asm.OpReg:
			if op == "MOVW" && isX86SystemOrSegIdent(string(src.Reg)) {
				return true, false, fmt.Errorf("%s: unsupported %s reading segment/system register %s: %q", c.goarch, op, src.Reg, ins.Raw)
			}
			v64, err := c.loadReg(src.Reg)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v64, widthTy)
			small = "%" + tr
		case asm.OpFP:
			v64, err := c.evalFPToI64(src.FPOffset)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v64, widthTy)
			small = "%" + tr
		case asm.OpMem:
			p, ptrType, err := c.ptrFromMem(src.Mem)
			if err != nil {
				return true, false, err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", ld, widthTy, ptrType, p)
			small = "%" + ld
		case asm.OpSym:
			p, err := c.ptrFromSB(src.Sym)
			if err != nil {
				return true, false, err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, widthTy, p)
			small = "%" + ld
		case asm.OpIdent:
			if op == "MOVW" && isX86SystemOrSegIdent(src.Ident) {
				return true, false, fmt.Errorf("%s: unsupported %s reading segment/system register %s: %q", c.goarch, op, src.Ident, ins.Raw)
			}
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		}
		switch dst.Kind {
		case asm.OpReg:
			if op == "MOVW" && isX86SystemOrSegIdent(string(dst.Reg)) {
				if c.goarch == "386" && strings.EqualFold(string(dst.Reg), "GS") {
					fmt.Fprintf(c.b, "  call void asm sideeffect \"movw $0, %%gs\", \"r,~{memory}\"(i16 %s)\n", small)
					return true, false, nil
				}
				return true, false, fmt.Errorf("%s: unsupported %s writing segment/system register %s: %q", c.goarch, op, dst.Reg, ins.Raw)
			}
			if zeroExtendSmallDst {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", z, widthTy, small)
				return true, false, c.storeReg(dst.Reg, "%"+z)
			}
			return true, false, c.storeRegSized(dst.Reg, widthTy, small)
		case asm.OpFP:
			return true, false, c.storeFPResult(dst.FPOffset, widthTy, small)
		case asm.OpMem:
			p, ptrType, err := c.ptrFromMem(dst.Mem)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", widthTy, small, ptrType, p)
			return true, false, nil
		case asm.OpSym:
			if !strings.HasSuffix(strings.TrimSpace(dst.Sym), "(SB)") {
				return true, false, fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
			}
			p, err := c.ptrFromSB(dst.Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", widthTy, small, p)
			return true, false, nil
		case asm.OpIdent:
			if op == "MOVW" && isX86SystemOrSegIdent(dst.Ident) {
				if c.goarch == "386" && strings.EqualFold(dst.Ident, "GS") {
					fmt.Fprintf(c.b, "  call void asm sideeffect \"movw $0, %%gs\", \"r,~{memory}\"(i16 %s)\n", small)
					return true, false, nil
				}
				return true, false, fmt.Errorf("%s: unsupported %s writing segment/system register %s: %q", c.goarch, op, dst.Ident, ins.Raw)
			}
			return true, false, fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
		}

	case "MOVQ":
		// MOVQ src, dst
		switch dst.Kind {
		case asm.OpReg:
			var v string
			var err error
			if src.Kind == asm.OpMem && src.Mem.Segment != "" {
				p, ptrType, err2 := c.ptrFromMem(src.Mem)
				if err2 != nil {
					return true, false, err2
				}
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i64, %s %s, align 1\n", t, ptrType, p)
				v = "%" + t
			} else {
				v, err = c.evalI64(src)
			}
			if err != nil {
				// Allow MOVQ mem, reg.
				if src.Kind == asm.OpMem {
					addr, err2 := c.addrFromMem(src.Mem)
					if err2 != nil {
						return true, false, err2
					}
					p := c.ptrFromAddrI64(addr)
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", t, p)
					v = "%" + t
				} else {
					return true, false, err
				}
			}
			return true, false, c.storeReg(dst.Reg, v)
		case asm.OpFP:
			// Store low 64 bits to a return slot if present.
			v, err := c.evalI64(src)
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeFPResult(dst.FPOffset, asm.I64, v)
		case asm.OpMem:
			// Store i64 to memory (common for writing return values via a pointer).
			if (src.Kind == asm.OpIdent && isX86SystemOrSegIdent(src.Ident)) ||
				(src.Kind == asm.OpReg && isX86SystemOrSegIdent(string(src.Reg))) {
				return true, false, fmt.Errorf("%s: unsupported MOVQ reading segment/system register: %q", c.goarch, ins.Raw)
			}
			v, err := c.evalI64(src)
			if err != nil {
				return true, false, err
			}
			p, ptrType, err := c.ptrFromMem(dst.Mem)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i64 %s, %s %s, align 1\n", v, ptrType, p)
			return true, false, nil
		case asm.OpSym:
			if !strings.HasSuffix(strings.TrimSpace(dst.Sym), "(SB)") {
				return true, false, fmt.Errorf("%w: unresolved store destination: %s", asm.ErrProbeNeedsContext, dst.Sym)
			}
			v, err := c.evalI64(src)
			if err != nil {
				return true, false, err
			}
			p, err := c.ptrFromSB(dst.Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", v, p)
			return true, false, nil
		case asm.OpIdent:
			if isX86SystemOrSegIdent(dst.Ident) {
				return true, false, fmt.Errorf("%s: unsupported MOVQ writing segment/system register %s: %q", c.goarch, dst.Ident, ins.Raw)
			}
			return true, false, fmt.Errorf("amd64 MOVQ unsupported dst: %q", ins.Raw)
		default:
			return true, false, fmt.Errorf("amd64 MOVQ unsupported dst: %q", ins.Raw)
		}

	case "MOVL":
		// MOVL src, dst
		if c.goarch != "386" && dst.Kind == asm.OpFP {
			// Preserve the established amd64 ABI result-slot lowering.
			if src.Kind != asm.OpReg {
				return true, false, fmt.Errorf("amd64 MOVL expects reg, fp for stores: %q", ins.Raw)
			}
			v64, err := c.loadReg(src.Reg)
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeFPResult(dst.FPOffset, asm.I64, v64)
		}

		i32v, err := c.evalIntSized(src, asm.I32)
		if err != nil {
			if (src.Kind == asm.OpIdent && isX86SystemOrSegIdent(src.Ident)) || (src.Kind == asm.OpReg && isX86SystemOrSegIdent(string(src.Reg))) {
				return true, false, fmt.Errorf("%s: unsupported MOVL reading segment/system register: %q", c.goarch, ins.Raw)
			}
			return true, false, err
		}
		switch dst.Kind {
		case asm.OpReg:
			// Zero-extend to 64-bit.
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, i32v)
			return true, false, c.storeReg(dst.Reg, "%"+z)

		case asm.OpFP:
			// Store low 32 bits (common for ret slots).
			return true, false, c.storeFPResult(dst.FPOffset, asm.I32, i32v)
		case asm.OpMem:
			p, ptrType, err := c.ptrFromMem(dst.Mem)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i32 %s, %s %s, align 1\n", i32v, ptrType, p)
			return true, false, nil
		case asm.OpImm:
			// Absolute-address writes in crash stubs must survive optimization.
			if dst.ImmRaw != "" {
				return true, false, fmt.Errorf("unresolved MOVL destination %s", dst.ImmRaw)
			}
			fmt.Fprintf(c.b, "  store volatile i32 %s, ptr inttoptr (i64 %d to ptr), align 1\n", i32v, dst.Imm)
			return true, false, nil
		case asm.OpSym:
			if !strings.HasSuffix(strings.TrimSpace(dst.Sym), "(SB)") {
				addr, ok := asm.ParseImmExpr(dst.Sym)
				if !ok {
					return true, false, fmt.Errorf("%w: unresolved store destination: %s", asm.ErrProbeNeedsContext, dst.Sym)
				}
				fmt.Fprintf(c.b, "  store volatile i32 %s, ptr inttoptr (i64 %d to ptr), align 1\n", i32v, addr)
				return true, false, nil
			}
			p, err := c.ptrFromSB(dst.Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i32 %s, ptr %s, align 1\n", i32v, p)
			return true, false, nil
		case asm.OpIdent:
			if isX86SystemOrSegIdent(dst.Ident) {
				return true, false, fmt.Errorf("%s: unsupported MOVL writing segment/system register %s: %q", c.goarch, dst.Ident, ins.Raw)
			}
			return true, false, fmt.Errorf("amd64 MOVL unsupported dst: %q", ins.Raw)
		default:
			return true, false, fmt.Errorf("amd64 MOVL unsupported dst: %q", ins.Raw)
		}
	}
	return false, false, nil
}
