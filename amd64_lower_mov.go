package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerMov(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerMOVNTI(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerMOVBE(op, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "MOVQ", "MOVD", "MOVL", "MOVB", "MOVW", "CMOVQLT",
		"MOVBWSX", "MOVBWZX", "MOVBLSX", "MOVBLZX", "MOVBQSX", "MOVBQZX",
		"MOVWLSX", "MOVWLZX", "MOVWQSX", "MOVWQZX", "MOVLQSX", "MOVLQZX",
		"MOVSWW", "MOVZWW":
		// ok
	default:
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("amd64 %s expects 2 operands: %q", op, ins.Raw)
	}
	if _, ok := amd64ScalarExtensionMoveSpecs[op]; ok {
		return true, false, c.lowerScalarExtensionMove(op, ins)
	}
	src, dst := ins.Args[0], ins.Args[1]
	if op == "MOVD" {
		op = "MOVQ"
	}

	// Vector moves are handled in lowerVec.
	if dst.Kind == OpReg {
		if _, ok := amd64ParseXReg(dst.Reg); ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(dst.Reg); ok {
			return false, false, nil
		}
	}
	if src.Kind == OpReg {
		if _, ok := amd64ParseXReg(src.Reg); ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(src.Reg); ok {
			return false, false, nil
		}
	}

	switch op {
	case "CMOVQLT":
		// CMOVQLT srcReg, dstReg
		if src.Kind != OpReg || dst.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 CMOVQLT expects reg, reg: %q", ins.Raw)
		}
		cond := c.loadFlag(c.flagsSltSlot)
		sv, err := c.loadReg(src.Reg)
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
		widthTy := I8
		if op == "MOVW" {
			widthTy = I16
		} else {
			// ymovb uses Yrb for register operands on both sides.  The
			// compatibility closure through Ymb is identical for registers,
			// including Go's synthesized BP/SI/DI support on 386, but excludes
			// the amd64-only explicit low-byte aliases when translating 386.
			if src.Kind == OpReg && !isGoYmbRegisterForArch(src.Reg, c.goarch) {
				return true, false, fmt.Errorf("amd64 MOVB source register is outside its Go 1.27 class: %q", ins.Raw)
			}
			if dst.Kind == OpReg && !isGoYmbRegisterForArch(dst.Reg, c.goarch) {
				return true, false, fmt.Errorf("amd64 MOVB destination register is outside its Go 1.27 class: %q", ins.Raw)
			}
		}
		var small string
		switch src.Kind {
		case OpImm:
			small = fmt.Sprintf("%d", src.Imm)
		case OpReg:
			v64, err := c.loadReg(src.Reg)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v64, widthTy)
			small = "%" + tr
		case OpFP:
			v64, err := c.evalFPToI64(src.FPOffset)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v64, widthTy)
			small = "%" + tr
		case OpMem:
			p, ptrType, err := c.ptrFromMem(src.Mem)
			if err != nil {
				return true, false, err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", ld, widthTy, ptrType, p)
			small = "%" + ld
		case OpSym:
			p, err := c.ptrFromSB(src.Sym)
			if err != nil {
				return true, false, err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, widthTy, p)
			small = "%" + ld
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		}
		switch dst.Kind {
		case OpReg:
			return true, false, c.storeRegSized(dst.Reg, widthTy, small)
		case OpFP:
			return true, false, c.storeFPResult(dst.FPOffset, widthTy, small)
		case OpMem:
			p, ptrType, err := c.ptrFromMem(dst.Mem)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", widthTy, small, ptrType, p)
			return true, false, nil
		case OpSym:
			if !strings.HasSuffix(strings.TrimSpace(dst.Sym), "(SB)") {
				return true, false, fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
			}
			p, err := c.ptrFromSB(dst.Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", widthTy, small, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
		}

	case "MOVQ":
		// MOVQ src, dst
		switch dst.Kind {
		case OpReg:
			var v string
			var err error
			if src.Kind == OpMem && src.Mem.Segment != "" {
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
				if src.Kind == OpMem {
					addr, err2 := c.addrFromMem(src.Mem)
					if err2 != nil {
						return true, false, err2
					}
					p := c.ptrFromAddrI64(addr)
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", t, p)
					v = "%" + t
				} else if src.Kind == OpSym {
					p, err2 := c.ptrFromSB(src.Sym)
					if err2 != nil {
						return true, false, err2
					}
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", t, p)
					v = "%" + t
				} else {
					return true, false, err
				}
			}
			return true, false, c.storeReg(dst.Reg, v)
		case OpFP:
			// Store low 64 bits to a return slot if present.
			v, err := c.evalI64(src)
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeFPResult(dst.FPOffset, I64, v)
		case OpMem:
			// Store i64 to memory (common for writing return values via a pointer).
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
		case OpSym:
			if !strings.HasSuffix(strings.TrimSpace(dst.Sym), "(SB)") {
				return true, false, nil
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
		default:
			return true, false, fmt.Errorf("amd64 MOVQ unsupported dst: %q", ins.Raw)
		}

	case "MOVL":
		// MOVL src, dst
		// FP result slots are memory operands in Go's ymovl table, so only a
		// GP register or a 32-bit immediate can write them. Vector-register
		// rows are handled by lowerVec before this scalar lowerer.
		if dst.Kind == OpFP && src.Kind != OpReg && src.Kind != OpImm {
			return true, false, fmt.Errorf("%s MOVL does not allow memory-to-result-memory: %q", c.goarch, ins.Raw)
		}

		i32v, err := c.evalIntSized(src, I32)
		if err != nil {
			// Preserve MOVL's existing treatment of unresolved constants from
			// assembly include files. Explicit `$symbol(SB)` addresses are handled
			// by evalIntSized above.
			if src.Kind != OpSym || strings.Contains(src.Sym, "(SB)") {
				return true, false, err
			}
			i32v = "0"
		}
		switch dst.Kind {
		case OpReg:
			// Zero-extend to 64-bit.
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, i32v)
			return true, false, c.storeReg(dst.Reg, "%"+z)

		case OpFP:
			// Store low 32 bits (common for ret slots).
			return true, false, c.storeFPResult(dst.FPOffset, I32, i32v)
		case OpMem:
			p, ptrType, err := c.ptrFromMem(dst.Mem)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i32 %s, %s %s, align 1\n", i32v, ptrType, p)
			return true, false, nil
		case OpImm:
			// Some runtime stubs intentionally encode a crashing instruction as
			// "MOVL $0xf1, 0xf1". Keep translation progressing.
			return true, false, nil
		case OpSym:
			if !strings.HasSuffix(strings.TrimSpace(dst.Sym), "(SB)") {
				// Crash marker form (e.g. MOVL $0xf1, 0xf1) in runtime stubs.
				return true, false, nil
			}
			p, err := c.ptrFromSB(dst.Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i32 %s, ptr %s, align 1\n", i32v, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 MOVL unsupported dst: %q", ins.Raw)
		}
	}
	return false, false, nil
}
