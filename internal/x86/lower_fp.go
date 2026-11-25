package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strconv"
	"strings"
)

func (c *amd64Ctx) lowerFP(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	if raw := string(op); strings.Contains(raw, ".") {
		if i := strings.IndexByte(raw, '.'); i >= 0 {
			op = asm.Op(raw[:i])
		}
	}
	switch op {
	case "MOVSD", "MOVAPD", "ANDPD", "ANDNPD", "ORPD", "XORPS",
		"ADDSD", "SUBSD", "MULSD", "DIVSD", "MAXSD", "MINSD", "SQRTSD",
		"COMISD", "CMPSD", "CMPSS", "CMPPS", "CMPPD", "VADDSD", "VFMADD213SD", "VFNMADD231SD",
		"CVTSD2SL", "CVTSL2SD", "CVTSQ2SD", "CVTTSD2SQ":
		// handled below
	default:
		return false, false, nil
	}

	switch op {
	case "MOVAPD", "ANDPD", "ANDNPD", "ORPD", "XORPS":
		if op == "MOVAPD" && len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpReg && (ins.Args[1].Kind == asm.OpMem || ins.Args[1].Kind == asm.OpSym) {
			if _, ok := amd64ParseXReg(ins.Args[0].Reg); ok {
				v, err := c.loadX(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				if ins.Args[1].Kind == asm.OpMem {
					p, ptrType, err := c.ptrFromMem(ins.Args[1].Mem)
					if err != nil {
						return true, false, err
					}
					fmt.Fprintf(c.b, "  store <16 x i8> %s, %s %s, align 1\n", v, ptrType, p)
					return true, false, nil
				}
				p, err := c.ptrFromSB(ins.Args[1].Sym)
				if err != nil {
					return true, false, err
				}
				fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", v, p)
				return true, false, nil
			}
		}
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		dst := ins.Args[1].Reg
		srcv, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		if op == "MOVAPD" {
			return true, false, c.storeX(dst, srcv)
		}
		dstv, err := c.loadX(dst)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		switch op {
		case "ANDPD":
			fmt.Fprintf(c.b, "  %%%s = and <16 x i8> %s, %s\n", t, dstv, srcv)
		case "ORPD":
			fmt.Fprintf(c.b, "  %%%s = or <16 x i8> %s, %s\n", t, dstv, srcv)
		case "XORPS":
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", t, dstv, srcv)
		case "ANDNPD":
			notv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", notv, dstv, llvmAllOnesI8Vec(16))
			fmt.Fprintf(c.b, "  %%%s = and <16 x i8> %%%s, %s\n", t, notv, srcv)
		}
		return true, false, c.storeX(dst, "%"+t)

	case "MOVSD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 MOVSD expects src, dst: %q", ins.Raw)
		}
		v, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		switch ins.Args[1].Kind {
		case asm.OpReg:
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
				return true, false, fmt.Errorf("amd64 MOVSD expects X-reg destination: %q", ins.Raw)
			}
			return true, false, c.storeXLowF64(ins.Args[1].Reg, v)
		case asm.OpFP:
			return true, false, c.storeFPResult(ins.Args[1].FPOffset, asm.LLVMType("double"), v)
		case asm.OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store double %s, ptr %s, align 1\n", v, p)
			return true, false, nil
		case asm.OpSym:
			p, err := c.ptrFromSB(ins.Args[1].Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store double %s, ptr %s, align 1\n", v, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 MOVSD unsupported destination: %q", ins.Raw)
		}

	case "ADDSD", "SUBSD", "MULSD", "DIVSD", "MAXSD", "MINSD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadXLowF64(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		switch op {
		case "ADDSD":
			fmt.Fprintf(c.b, "  %%%s = fadd double %s, %s\n", t, dst, src)
		case "SUBSD":
			fmt.Fprintf(c.b, "  %%%s = fsub double %s, %s\n", t, dst, src)
		case "MULSD":
			fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", t, dst, src)
		case "DIVSD":
			fmt.Fprintf(c.b, "  %%%s = fdiv double %s, %s\n", t, dst, src)
		case "MAXSD":
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp ogt double %s, %s\n", cmp, dst, src)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %s, double %s\n", t, cmp, dst, src)
		case "MINSD":
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp olt double %s, %s\n", cmp, dst, src)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %s, double %s\n", t, cmp, dst, src)
		}
		return true, false, c.storeXLowF64(ins.Args[1].Reg, "%"+t)

	case "SQRTSD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 SQRTSD expects src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.sqrt.f64(double %s)\n", t, src)
		return true, false, c.storeXLowF64(ins.Args[1].Reg, "%"+t)

	case "COMISD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 COMISD expects src, dst: %q", ins.Raw)
		}
		src, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst, err := c.evalF64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp ueq double %s, %s\n", z, dst, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp ult double %s, %s\n", cf, dst, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		lt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp olt double %s, %s\n", lt, dst, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", lt, c.flagsSltSlot)
		return true, false, nil

	case "CMPSD", "CMPSS", "CMPPS", "CMPPD":
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("amd64 %s expects 3 operands: %q", op, ins.Raw)
		}
		var srcOp, dstOp, immOp asm.Operand
		if ins.Args[1].Kind == asm.OpReg && isAMD64XReg(ins.Args[1].Reg) {
			srcOp, dstOp, immOp = ins.Args[0], ins.Args[1], ins.Args[2]
		} else if ins.Args[2].Kind == asm.OpReg && isAMD64XReg(ins.Args[2].Reg) {
			immOp, srcOp, dstOp = ins.Args[0], ins.Args[1], ins.Args[2]
		} else if ins.Args[1].Kind == asm.OpReg {
			return false, false, nil
		} else {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst, $imm: %q", op, ins.Raw)
		}
		pred := int64(0)
		switch immOp.Kind {
		case asm.OpImm:
			pred = immOp.Imm
		case asm.OpSym:
			n, err := strconv.ParseInt(strings.TrimSpace(immOp.Sym), 0, 64)
			if err != nil {
				return true, false, fmt.Errorf("amd64 %s invalid imm %q: %q", op, immOp.Sym, ins.Raw)
			}
			pred = n
		default:
			return true, false, fmt.Errorf("amd64 %s expects immediate predicate: %q", op, ins.Raw)
		}
		fcmpPred := [8]string{"oeq", "olt", "ole", "uno", "une", "uge", "ugt", "ord"}[pred&7]
		switch op {
		case "CMPSD":
			src, err := c.evalF64(srcOp)
			if err != nil {
				return true, false, err
			}
			dst, err := c.loadXLowF64(dstOp.Reg)
			if err != nil {
				return true, false, err
			}
			cmp, mask := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp %s double %s, %s\n", cmp, fcmpPred, dst, src)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 -1, i64 0\n", mask, cmp)
			return true, false, c.storeXLowI64(dstOp.Reg, "%"+mask)
		case "CMPSS":
			src, err := c.evalF32(srcOp)
			if err != nil {
				return true, false, err
			}
			dst, err := c.loadXLowF32(dstOp.Reg)
			if err != nil {
				return true, false, err
			}
			cmp, mask, fmask := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp %s float %s, %s\n", cmp, fcmpPred, dst, src)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 -1, i32 0\n", mask, cmp)
			fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", fmask, mask)
			return true, false, c.storeXLowF32(dstOp.Reg, "%"+fmask)
		case "CMPPS", "CMPPD":
			srcRaw, err := c.loadXVecOperand(srcOp)
			if err != nil {
				return true, false, err
			}
			dstRaw, err := c.loadX(dstOp.Reg)
			if err != nil {
				return true, false, err
			}
			lanes, fpTy, intTy := 4, "<4 x float>", "<4 x i32>"
			if op == "CMPPD" {
				lanes, fpTy, intTy = 2, "<2 x double>", "<2 x i64>"
			}
			sb, db, cmp, sx, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", sb, srcRaw, fpTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", db, dstRaw, fpTy)
			fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %%%s, %%%s\n", cmp, fcmpPred, fpTy, db, sb)
			fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", sx, lanes, cmp, intTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, intTy, sx)
			return true, false, c.storeX(dstOp.Reg, "%"+out)
		}

	case "CVTTSD2SQ":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 CVTTSD2SQ expects src, dstReg: %q", ins.Raw)
		}
		src, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptosi double %s to i64\n", t, src)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+t)

	case "CVTSQ2SD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 CVTSQ2SD expects src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp i64 %s to double\n", t, src)
		return true, false, c.storeXLowF64(ins.Args[1].Reg, "%"+t)

	case "CVTSD2SL":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 CVTSD2SL expects src, dstReg: %q", ins.Raw)
		}
		src, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		round := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.rint.f64(double %s)\n", round, src)
		i32v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptosi double %%%s to i32\n", i32v, round)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, i32v)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)

	case "CVTSL2SD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 CVTSL2SD expects srcReg, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		i32v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", i32v, src)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp i32 %%%s to double\n", t, i32v)
		return true, false, c.storeXLowF64(ins.Args[1].Reg, "%"+t)

	case "VADDSD":
		if len(ins.Args) != 3 {
			return false, false, nil
		}
		if ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 VADDSD expects src1, src2, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		s1, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		s2, err := c.evalF64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fadd double %s, %s\n", t, s2, s1)
		return true, false, c.storeXLowF64(ins.Args[2].Reg, "%"+t)

	case "VFMADD213SD", "VFNMADD231SD":
		args, kreg, hasMask := x86StripEVEXMask(ins.Args)
		zeroMask := strings.Contains(strings.ToUpper(string(ins.Op)), ".Z")
		if len(args) != 3 || args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src1, src2, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(args[2].Reg); !ok {
			return false, false, nil
		}
		s1, err := c.evalF64(args[0])
		if err != nil {
			return true, false, err
		}
		s2, err := c.evalF64(args[1])
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadXLowF64(args[2].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		if op == "VFMADD213SD" {
			mul := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", mul, dst, s2)
			fmt.Fprintf(c.b, "  %%%s = fadd double %%%s, %s\n", t, mul, s1)
		} else {
			mul, neg := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", mul, s1, s2)
			fmt.Fprintf(c.b, "  %%%s = fneg double %%%s\n", neg, mul)
			fmt.Fprintf(c.b, "  %%%s = fadd double %%%s, %s\n", t, neg, dst)
		}
		out := "%" + t
		if hasMask {
			kv, err := c.loadK(kreg)
			if err != nil {
				return true, false, err
			}
			bit, sel := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", bit, kv)
			fb := dst
			if zeroMask {
				fb = "0.0"
			}
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %s, double %s\n", sel, bit, out, fb)
			out = "%" + sel
		}
		return true, false, c.storeXLowF64(args[2].Reg, out)
	}
	return false, false, nil
}

func (c *amd64Ctx) loadXVecOperand(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpReg:
		if _, ok := amd64ParseXReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected X register operand, got %s", op.String())
		}
		return c.loadX(op.Reg)
	case asm.OpMem:
		addr, err := c.addrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		p := c.ptrFromAddrI64(addr)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported X-vector operand %s", op.String())
	}
}

func (c *amd64Ctx) loadYVecOperand(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpReg:
		if _, ok := amd64ParseYReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected Y register operand, got %s", op.String())
		}
		return c.loadY(op.Reg)
	case asm.OpMem:
		addr, err := c.addrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		p := c.ptrFromAddrI64(addr)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <32 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <32 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported Y-vector operand %s", op.String())
	}
}

func (c *amd64Ctx) loadZVecOperand(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpReg:
		if _, ok := amd64ParseZReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected Z register operand, got %s", op.String())
		}
		return c.loadZ(op.Reg)
	case asm.OpMem:
		addr, err := c.addrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		p := c.ptrFromAddrI64(addr)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <64 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <64 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported Z-vector operand %s", op.String())
	}
}

func (c *amd64Ctx) loadXLowI64(r asm.Reg) (string, error) {
	xv, err := c.loadX(r)
	if err != nil {
		return "", err
	}
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, xv)
	lo := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", lo, bc)
	return "%" + lo, nil
}

func (c *amd64Ctx) loadXLowF64(r asm.Reg) (string, error) {
	lo, err := c.loadXLowI64(r)
	if err != nil {
		return "", err
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, lo)
	return "%" + t, nil
}

func (c *amd64Ctx) storeXLowI64(r asm.Reg, low string) error {
	cur, err := c.loadX(r)
	if err != nil {
		return err
	}
	cur2 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", cur2, cur)
	hi := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 1\n", hi, cur2)
	v0 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %s, i32 0\n", v0, low)
	v1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %%%s, i32 1\n", v1, v0, hi)
	back := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", back, v1)
	return c.storeX(r, "%"+back)
}

func (c *amd64Ctx) storeXLowF64(r asm.Reg, v string) error {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, v)
	return c.storeXLowI64(r, "%"+t)
}

func (c *amd64Ctx) evalF64(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpReg:
		if _, ok := amd64ParseXReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected X register for f64 operand, got %s", op.String())
		}
		return c.loadXLowF64(op.Reg)
	case asm.OpImm:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %d to double\n", t, op.Imm)
		return "%" + t, nil
	case asm.OpFP:
		return c.evalFPToF64(op.FPOffset)
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load double, %s %s, align 1\n", ld, ptrType, p)
		return "%" + ld, nil
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load double, ptr %s, align 1\n", ld, p)
		return "%" + ld, nil
	default:
		return "", fmt.Errorf("amd64: unsupported f64 operand %s", op.String())
	}
}

func (c *amd64Ctx) evalFPToF64(off int64) (string, error) {
	slot, ok := c.fpParam(off)
	if !ok {
		return "", fmt.Errorf("unsupported FP read slot for f64: +%d(FP)", off)
	}
	idx := slot.Index
	if idx < 0 || idx >= len(c.sig.Args) {
		return "", fmt.Errorf("FP read slot for f64: invalid arg index %d at +%d(FP)", idx, off)
	}
	arg := fmt.Sprintf("%%arg%d", idx)
	ty := slot.Type
	if c.classicFrame != "" {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", loaded, ty, c.classicFramePtr(off))
		arg = "%" + loaded
	} else if len(slot.Fields) > 0 || slot.Field >= 0 {
		arg = c.extractFrameSlotArg(c.sig.Args[idx], arg, slot)
	}
	switch ty {
	case asm.LLVMType("double"):
		return arg, nil
	case asm.I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, arg)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("FP read unsupported type %q for f64 at +%d(FP)", ty, off)
	}
}
