package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func (c *amd64Ctx) lowerFP(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, term, err := c.lowerApproximateMath(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerFixupImmediate(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerScaledRound(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerGetMant(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerGetExp(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerFPClass(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerFloatingRange(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerReciprocal14(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerReciprocalEstimate(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerRound(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerScalarFloatToInteger(op, ins); ok {
		return ok, term, err
	}
	if raw := strings.ToUpper(string(op)); raw != "" {
		base := raw
		if dot := strings.IndexByte(raw, '.'); dot >= 0 {
			base = raw[:dot]
		}
		if _, recognized := amd64HorizontalFloatingSpecs[Op(base)]; recognized {
			return c.lowerHorizontalFloating(op, ins)
		}
	}
	if raw := strings.ToUpper(string(op)); raw != "" {
		base := raw
		if dot := strings.IndexByte(raw, '.'); dot >= 0 {
			base = raw[:dot]
		}
		if _, recognized := amd64BinaryFloatingSpecs[Op(base)]; recognized {
			return c.lowerBinaryFloating(op, ins)
		}
	}
	if raw := strings.ToUpper(string(op)); raw != "" {
		base := raw
		if dot := strings.IndexByte(raw, '.'); dot >= 0 {
			base = raw[:dot]
		}
		if _, recognized := amd64FMA3Specs[Op(base)]; recognized {
			return c.lowerFMA3(op, ins)
		}
	}
	if raw := strings.ToUpper(string(op)); raw != "" {
		base := raw
		if dot := strings.IndexByte(raw, '.'); dot >= 0 {
			base = raw[:dot]
		}
		if _, recognized := amd64PackedFloatingLogicalSpecs[Op(base)]; recognized {
			return c.lowerPackedFloatingLogical(op, ins)
		}
	}
	if raw := strings.ToUpper(string(op)); raw != "" {
		base := raw
		if dot := strings.IndexByte(raw, '.'); dot >= 0 {
			base = raw[:dot]
		}
		if base == "VCVTSS2SD" || base == "VCVTSD2SS" {
			return c.lowerVEXScalarFloatConvert(op, ins)
		}
	}
	switch op {
	case "MOVSS", "MOVSD", "MOVAPD", "MOVUPD",
		"ADDSS", "SUBSS", "MULSS", "DIVSS", "MAXSS", "MINSS", "SQRTSS",
		"ADDPS", "SUBPS", "MULPS", "DIVPS", "MAXPS", "MINPS",
		"ADDPD", "SUBPD", "MULPD", "DIVPD", "MAXPD", "MINPD",
		"SQRTPS", "SQRTPD",
		"MOVLHPS", "MOVHLPS", "MOVLPS", "MOVHPS", "MOVLPD", "MOVHPD",
		"VMOVLPS", "VMOVHPS", "VMOVLPD", "VMOVHPD", "SHUFPD", "UNPCKLPS", "UNPCKHPD",
		"ADDSD", "SUBSD", "MULSD", "DIVSD", "MAXSD", "MINSD", "SQRTSD",
		"COMISS", "UCOMISS", "COMISD", "UCOMISD", "CMPSD",
		"CVTSS2SD", "VCVTSS2SD", "CVTSD2SS", "VCVTSD2SS", "CVTSL2SD", "CVTSQ2SD":
		// handled below
	default:
		return false, false, nil
	}

	switch op {
	case "VCVTSS2SD":
		return c.lowerVEXScalarFloatConvert(op, ins)

	case "VCVTSD2SS":
		return c.lowerVEXScalarFloatConvert(op, ins)

	case "MOVAPD", "MOVUPD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		if ins.Args[1].Kind == OpReg {
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
				return false, false, nil
			}
			srcv, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeX(ins.Args[1].Reg, srcv)
		}
		if ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s store expects X source: %q", op, ins.Raw)
		}
		srcv, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		if err := c.storeXVecOperand(ins.Args[1], srcv); err != nil {
			return true, false, fmt.Errorf("amd64 %s unsupported destination %s: %w", op, ins.Args[1].String(), err)
		}
		return true, false, nil

	case "MOVSS":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 MOVSS expects src, dst: %q", ins.Raw)
		}
		v, err := c.evalF32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		switch ins.Args[1].Kind {
		case OpReg:
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
				return true, false, fmt.Errorf("amd64 MOVSS expects X-reg destination: %q", ins.Raw)
			}
			if ins.Args[0].Kind == OpReg {
				return true, false, c.storeXLowF32(ins.Args[1].Reg, v)
			}
			return true, false, c.storeXLowF32ClearingUpper(ins.Args[1].Reg, v)
		case OpFP:
			return true, false, c.storeFPResult(ins.Args[1].FPOffset, LLVMType("float"), v)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store float %s, ptr %s, align 1\n", v, c.ptrFromAddrI64(addr))
			return true, false, nil
		case OpSym:
			p, err := c.ptrFromSB(ins.Args[1].Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store float %s, ptr %s, align 1\n", v, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 MOVSS unsupported destination: %q", ins.Raw)
		}

	case "ADDSS", "SUBSS", "MULSS", "DIVSS", "MAXSS", "MINSS":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalF32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadXLowF32(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		value := c.newTmp()
		switch op {
		case "ADDSS":
			fmt.Fprintf(c.b, "  %%%s = fadd float %s, %s\n", value, dst, src)
		case "SUBSS":
			fmt.Fprintf(c.b, "  %%%s = fsub float %s, %s\n", value, dst, src)
		case "MULSS":
			fmt.Fprintf(c.b, "  %%%s = fmul float %s, %s\n", value, dst, src)
		case "DIVSS":
			fmt.Fprintf(c.b, "  %%%s = fdiv float %s, %s\n", value, dst, src)
		case "MAXSS", "MINSS":
			cmp := c.newTmp()
			pred := "ogt"
			if op == "MINSS" {
				pred = "olt"
			}
			fmt.Fprintf(c.b, "  %%%s = fcmp %s float %s, %s\n", cmp, pred, dst, src)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, float %s, float %s\n", value, cmp, dst, src)
		}
		return true, false, c.storeXLowF32(ins.Args[1].Reg, "%"+value)

	case "SQRTSS":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 SQRTSS expects src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalF32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call float @llvm.sqrt.f32(float %s)\n", value, src)
		return true, false, c.storeXLowF32(ins.Args[1].Reg, "%"+value)

	case "ADDPS", "SUBPS", "MULPS", "DIVPS", "MAXPS", "MINPS",
		"ADDPD", "SUBPD", "MULPD", "DIVPD", "MAXPD", "MINPD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		vectorType := "<4 x float>"
		if strings.HasSuffix(string(op), "PD") {
			vectorType = "<2 x double>"
		}
		src, err := c.loadXTypedVectorOperand(ins.Args[0], vectorType)
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadXTypedVectorOperand(ins.Args[1], vectorType)
		if err != nil {
			return true, false, err
		}
		value := c.newTmp()
		switch {
		case strings.HasPrefix(string(op), "ADD"):
			fmt.Fprintf(c.b, "  %%%s = fadd %s %s, %s\n", value, vectorType, dst, src)
		case strings.HasPrefix(string(op), "SUB"):
			fmt.Fprintf(c.b, "  %%%s = fsub %s %s, %s\n", value, vectorType, dst, src)
		case strings.HasPrefix(string(op), "MUL"):
			fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %s\n", value, vectorType, dst, src)
		case strings.HasPrefix(string(op), "DIV"):
			fmt.Fprintf(c.b, "  %%%s = fdiv %s %s, %s\n", value, vectorType, dst, src)
		default:
			cmp := c.newTmp()
			pred := "ogt"
			if strings.HasPrefix(string(op), "MIN") {
				pred = "olt"
			}
			lanes := 4
			if vectorType == "<2 x double>" {
				lanes = 2
			}
			fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, pred, vectorType, dst, src)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", value, lanes, cmp, vectorType, dst, vectorType, src)
		}
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytesValue, vectorType, value)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+bytesValue)

	case "SQRTPS", "SQRTPD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		vectorType := "<4 x float>"
		intrinsic := "@llvm.sqrt.v4f32"
		if op == "SQRTPD" {
			vectorType = "<2 x double>"
			intrinsic = "@llvm.sqrt.v2f64"
		}
		src, err := c.loadXTypedVectorOperand(ins.Args[0], vectorType)
		if err != nil {
			return true, false, err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s)\n", value, vectorType, intrinsic, vectorType, src)
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytesValue, vectorType, value)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+bytesValue)

	case "MOVLHPS", "MOVHLPS":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc, Xdst: %q", op, ins.Raw)
		}
		src, err := c.loadXAsI64x2(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadXAsI64x2(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		mask := "<i32 0, i32 2>"
		if op == "MOVHLPS" {
			mask = "<i32 3, i32 1>"
		}
		shuffled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <2 x i32> %s\n", shuffled, dst, src, mask)
		return true, false, c.storeXFromI64x2(ins.Args[1].Reg, "%"+shuffled)

	case "MOVLPS", "MOVHPS", "MOVLPD", "MOVHPD", "VMOVLPS", "VMOVHPS", "VMOVLPD", "VMOVHPD":
		return c.lowerMOVHalf(op, ins)

	case "SHUFPD":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 SHUFPD expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		src, err := c.loadXAsI64x2(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadXAsI64x2(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		lo := ins.Args[0].Imm & 1
		hi := 2 + ((ins.Args[0].Imm >> 1) & 1)
		shuffled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <2 x i32> <i32 %d, i32 %d>\n", shuffled, dst, src, lo, hi)
		return true, false, c.storeXFromI64x2(ins.Args[2].Reg, "%"+shuffled)

	case "UNPCKLPS", "UNPCKHPD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		vectorType := "<4 x float>"
		maskType := "<4 x i32>"
		mask := "<i32 0, i32 4, i32 1, i32 5>"
		if op == "UNPCKHPD" {
			vectorType = "<2 x double>"
			maskType = "<2 x i32>"
			mask = "<i32 1, i32 3>"
		}
		src, err := c.loadXTypedVectorOperand(ins.Args[0], vectorType)
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadXTypedVectorOperand(ins.Args[1], vectorType)
		if err != nil {
			return true, false, err
		}
		shuffled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s %s\n", shuffled, vectorType, dst, vectorType, src, maskType, mask)
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytesValue, vectorType, shuffled)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+bytesValue)

	case "MOVSD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 MOVSD expects src, dst: %q", ins.Raw)
		}
		v, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		switch ins.Args[1].Kind {
		case OpReg:
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
				return true, false, fmt.Errorf("amd64 MOVSD expects X-reg destination: %q", ins.Raw)
			}
			return true, false, c.storeXLowF64(ins.Args[1].Reg, v)
		case OpFP:
			return true, false, c.storeFPResult(ins.Args[1].FPOffset, LLVMType("double"), v)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store double %s, ptr %s, align 1\n", v, p)
			return true, false, nil
		case OpSym:
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
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
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
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
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

	case "COMISS", "UCOMISS":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		src, err := c.evalF32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst, err := c.evalF32(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		c.setScalarFloatCompareFlags(LLVMType("float"), dst, src)
		return true, false, nil

	case "COMISD", "UCOMISD":
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
		c.setScalarFloatCompareFlags(LLVMType("double"), dst, src)
		return true, false, nil

	case "CMPSD":
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 CMPSD expects src, Xdst, $imm: %q", ins.Raw)
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
		pred := int64(0)
		switch ins.Args[2].Kind {
		case OpImm:
			pred = ins.Args[2].Imm
		case OpSym:
			n, err := strconv.ParseInt(strings.TrimSpace(ins.Args[2].Sym), 0, 64)
			if err != nil {
				return true, false, fmt.Errorf("amd64 CMPSD invalid imm %q: %q", ins.Args[2].Sym, ins.Raw)
			}
			pred = n
		default:
			return true, false, fmt.Errorf("amd64 CMPSD expects immediate predicate: %q", ins.Raw)
		}
		pred &= 7
		cmp := c.newTmp()
		switch pred {
		case 0:
			fmt.Fprintf(c.b, "  %%%s = fcmp oeq double %s, %s\n", cmp, dst, src)
		case 1:
			fmt.Fprintf(c.b, "  %%%s = fcmp olt double %s, %s\n", cmp, dst, src)
		case 2:
			fmt.Fprintf(c.b, "  %%%s = fcmp ole double %s, %s\n", cmp, dst, src)
		case 3:
			fmt.Fprintf(c.b, "  %%%s = fcmp uno double %s, %s\n", cmp, dst, src)
		case 4:
			fmt.Fprintf(c.b, "  %%%s = fcmp une double %s, %s\n", cmp, dst, src)
		case 5:
			fmt.Fprintf(c.b, "  %%%s = fcmp uge double %s, %s\n", cmp, dst, src)
		case 6:
			fmt.Fprintf(c.b, "  %%%s = fcmp ugt double %s, %s\n", cmp, dst, src)
		case 7:
			fmt.Fprintf(c.b, "  %%%s = fcmp ord double %s, %s\n", cmp, dst, src)
		}
		mask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 -1, i64 0\n", mask, cmp)
		return true, false, c.storeXLowI64(ins.Args[1].Reg, "%"+mask)

	case "CVTSS2SD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 CVTSS2SD expects src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalF32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", converted, src)
		return true, false, c.storeXLowF64(ins.Args[1].Reg, "%"+converted)

	case "CVTSD2SS":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 CVTSD2SS expects src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", converted, src)
		return true, false, c.storeXLowF32(ins.Args[1].Reg, "%"+converted)

	case "CVTSQ2SD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
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

	case "CVTSL2SD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
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

	}
	return false, false, nil
}

func (c *amd64Ctx) loadXVecOperand(op Operand) (string, error) {
	switch op.Kind {
	case OpReg:
		if _, ok := amd64ParseXReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected X register operand, got %s", op.String())
		}
		return c.loadX(op.Reg)
	case OpMem:
		addr, err := c.addrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		p := c.ptrFromAddrI64(addr)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case OpFP:
		low, err := c.evalFPToI64(op.FPOffset)
		if err != nil {
			return "", err
		}
		high, err := c.evalFPToI64(op.FPOffset + 8)
		if err != nil {
			return "", err
		}
		lowLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %s, i32 0\n", lowLane, low)
		both := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %s, i32 1\n", both, lowLane, high)
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytesValue, both)
		return "%" + bytesValue, nil
	default:
		return "", fmt.Errorf("amd64: unsupported X-vector operand %s", op.String())
	}
}

func (c *amd64Ctx) storeXVecOperand(op Operand, value string) error {
	switch op.Kind {
	case OpReg:
		if !isAMD64XReg(op.Reg) {
			return fmt.Errorf("expected X register, got %s", op.String())
		}
		return c.storeX(op.Reg, value)
	case OpMem:
		addr, err := c.addrFromMem(op.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", value, c.ptrFromAddrI64(addr))
		return nil
	case OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", value, p)
		return nil
	case OpFP:
		lanes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", lanes, value)
		low := c.newTmp()
		high := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", low, lanes)
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 1\n", high, lanes)
		if err := c.storeFPResult(op.FPOffset, I64, "%"+low); err != nil {
			return err
		}
		return c.storeFPResult(op.FPOffset+8, I64, "%"+high)
	default:
		return fmt.Errorf("unsupported X-vector destination %s", op.String())
	}
}

func (c *amd64Ctx) loadYVecOperand(op Operand) (string, error) {
	switch op.Kind {
	case OpReg:
		if _, ok := amd64ParseYReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected Y register operand, got %s", op.String())
		}
		return c.loadY(op.Reg)
	case OpMem:
		addr, err := c.addrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		p := c.ptrFromAddrI64(addr)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <32 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case OpSym:
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

func (c *amd64Ctx) loadZVecOperand(op Operand) (string, error) {
	switch op.Kind {
	case OpReg:
		if _, ok := amd64ParseZReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected Z register operand, got %s", op.String())
		}
		return c.loadZ(op.Reg)
	case OpMem:
		addr, err := c.addrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		p := c.ptrFromAddrI64(addr)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <64 x i8>, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	case OpSym:
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

func (c *amd64Ctx) loadXLowI64(r Reg) (string, error) {
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

func (c *amd64Ctx) loadXLowF64(r Reg) (string, error) {
	lo, err := c.loadXLowI64(r)
	if err != nil {
		return "", err
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, lo)
	return "%" + t, nil
}

func (c *amd64Ctx) loadXLowF32(r Reg) (string, error) {
	xv, err := c.loadX(r)
	if err != nil {
		return "", err
	}
	words := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", words, xv)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %%%s, i32 0\n", low, words)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", value, low)
	return "%" + value, nil
}

func (c *amd64Ctx) storeXLowI64(r Reg, low string) error {
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

func (c *amd64Ctx) storeXLowF64(r Reg, v string) error {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, v)
	return c.storeXLowI64(r, "%"+t)
}

func (c *amd64Ctx) storeXLowF32(r Reg, v string) error {
	cur, err := c.loadX(r)
	if err != nil {
		return err
	}
	words := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", words, cur)
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bits, v)
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %%%s, i32 %%%s, i32 0\n", inserted, words, bits)
	back := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", back, inserted)
	return c.storeX(r, "%"+back)
}

func (c *amd64Ctx) storeXLowF32ClearingUpper(r Reg, v string) error {
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bits, v)
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> zeroinitializer, i32 %%%s, i32 0\n", inserted, bits)
	back := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", back, inserted)
	return c.storeX(r, "%"+back)
}

func (c *amd64Ctx) loadXTypedVectorOperand(op Operand, vectorType string) (string, error) {
	bytesValue, err := c.loadXVecOperand(op)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", value, bytesValue, vectorType)
	return "%" + value, nil
}

func (c *amd64Ctx) loadXAsI64x2(r Reg) (string, error) {
	if _, ok := amd64ParseXReg(r); !ok {
		return "", fmt.Errorf("amd64: expected X register, got %s", r)
	}
	bytesValue, err := c.loadX(r)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", value, bytesValue)
	return "%" + value, nil
}

func (c *amd64Ctx) storeXFromI64x2(r Reg, value string) error {
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %s to <16 x i8>\n", bytesValue, value)
	return c.storeX(r, "%"+bytesValue)
}

type amd64MoveHalfSpec struct {
	high   bool
	vector bool
}

// amd64MoveHalfSpecs is the complete Go 1.27 yxmov/_yvmovhpd family. Legacy
// register forms alias MOVHLPS/MOVLHPS; VEX/EVEX forms deliberately accept
// only memory loads (memory, upper-lane X, destination X) and memory stores.
var amd64MoveHalfSpecs = map[Op]amd64MoveHalfSpec{
	"MOVLPS":  {},
	"MOVHPS":  {high: true},
	"MOVLPD":  {},
	"MOVHPD":  {high: true},
	"VMOVLPS": {vector: true},
	"VMOVHPS": {high: true, vector: true},
	"VMOVLPD": {vector: true},
	"VMOVHPD": {high: true, vector: true},
}

func (c *amd64Ctx) lowerMOVHalf(op Op, ins Instr) (bool, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64MoveHalfSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.vector {
		return c.lowerVEXMOVHalf(baseOp, spec, ins)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", baseOp, ins.Raw)
	}
	destinationLane := int64(0)
	if spec.high {
		destinationLane = 1
	}
	if ins.Args[1].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's X register class: %q", baseOp, ins.Raw)
		}
		bits := ""
		if ins.Args[0].Kind == OpReg {
			if !c.isGoLegacyXReg(ins.Args[0].Reg) {
				return true, false, fmt.Errorf("amd64 %s source is outside Go 1.27's X register class: %q", baseOp, ins.Raw)
			}
			source, err := c.loadXAsI64x2(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			// Register encodings of the low/high moves alias MOVHLPS and
			// MOVLHPS respectively, regardless of the PS/PD prefix.
			sourceLane := int64(0)
			if destinationLane == 0 {
				sourceLane = 1
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %s, i32 %d\n", extracted, source, sourceLane)
			bits = "%" + extracted
		} else {
			if !isAMD64MemoryOperand(ins.Args[0]) {
				return true, false, fmt.Errorf("amd64 %s source must be X or memory: %q", baseOp, ins.Raw)
			}
			value, err := c.evalF64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			loadedBits := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", loadedBits, value)
			bits = "%" + loadedBits
		}
		cur, err := c.loadXAsI64x2(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %s, i64 %s, i32 %d\n", inserted, cur, bits, destinationLane)
		return true, false, c.storeXFromI64x2(ins.Args[1].Reg, "%"+inserted)
	}
	if ins.Args[0].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[0].Reg) || !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s store expects X source and memory destination: %q", baseOp, ins.Raw)
	}
	src, err := c.loadXAsI64x2(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %s, i32 %d\n", bits, src, destinationLane)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to double\n", value, bits)
	switch ins.Args[1].Kind {
	case OpFP:
		return true, false, c.storeFPResult(ins.Args[1].FPOffset, LLVMType("double"), "%"+value)
	case OpMem:
		addr, err := c.addrFromMem(ins.Args[1].Mem)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store double %%%s, ptr %s, align 1\n", value, c.ptrFromAddrI64(addr))
		return true, false, nil
	case OpSym:
		p, err := c.ptrFromSB(ins.Args[1].Sym)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store double %%%s, ptr %s, align 1\n", value, p)
		return true, false, nil
	default:
		return true, false, fmt.Errorf("amd64 %s unsupported destination: %q", baseOp, ins.Raw)
	}
}

func (c *amd64Ctx) lowerVEXMOVHalf(baseOp string, spec amd64MoveHalfSpec, ins Instr) (bool, bool, error) {
	lane := int64(0)
	if spec.high {
		lane = 1
	}
	if len(ins.Args) == 2 {
		if !c.isGoPackedVectorMoveRegister(ins.Args[0], 16) || !isAMD64MemoryOperand(ins.Args[1]) {
			return true, false, fmt.Errorf("%s %s store expects X source and memory destination: %q", c.goarch, baseOp, ins.Raw)
		}
		source, err := c.loadXAsI64x2(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %s, i32 %d\n", bits, source, lane)
		return true, false, c.storeMOVHalfBits(ins.Args[1], "%"+bits)
	}
	if len(ins.Args) != 3 || !isAMD64MemoryOperand(ins.Args[0]) ||
		!c.isGoPackedVectorMoveRegister(ins.Args[1], 16) || !c.isGoPackedVectorMoveRegister(ins.Args[2], 16) {
		return true, false, fmt.Errorf("%s %s load expects memory, upper-lane X, destination X: %q", c.goarch, baseOp, ins.Raw)
	}
	value, err := c.evalF64(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", bits, value)
	base, err := c.loadXAsI64x2(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %s, i64 %%%s, i32 %d\n", inserted, base, bits, lane)
	return true, false, c.storeXFromI64x2(ins.Args[2].Reg, "%"+inserted)
}

func (c *amd64Ctx) storeMOVHalfBits(destination Operand, bits string) error {
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", value, bits)
	switch destination.Kind {
	case OpFP:
		return c.storeFPResult(destination.FPOffset, LLVMType("double"), "%"+value)
	case OpMem:
		addr, err := c.addrFromMem(destination.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store double %%%s, ptr %s, align 1\n", value, c.ptrFromAddrI64(addr))
		return nil
	case OpSym:
		p, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store double %%%s, ptr %s, align 1\n", value, p)
		return nil
	default:
		return fmt.Errorf("unsupported half-vector destination %s", destination.String())
	}
}

func (c *amd64Ctx) lowerVEXScalarFloatConvert(op Op, ins Instr) (bool, bool, error) {
	rawOp := strings.ToUpper(string(op))
	parts := strings.Split(rawOp, ".")
	baseOp := parts[0]
	rounding := ""
	sae, zeroing := false, false
	for _, suffix := range parts[1:] {
		switch suffix {
		case "Z":
			if zeroing {
				return true, false, fmt.Errorf("%s %s repeats .Z: %q", c.goarch, baseOp, ins.Raw)
			}
			zeroing = true
		case "SAE":
			if baseOp != "VCVTSS2SD" || sae || rounding != "" {
				return true, false, fmt.Errorf("%s %s suffix .%s is absent from its Go 1.27 EVEX form: %q", c.goarch, baseOp, suffix, ins.Raw)
			}
			sae = true
		case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
			if baseOp != "VCVTSD2SS" || sae || rounding != "" {
				return true, false, fmt.Errorf("%s %s suffix .%s is absent from its Go 1.27 EVEX form: %q", c.goarch, baseOp, suffix, ins.Raw)
			}
			rounding = suffix
		default:
			return true, false, fmt.Errorf("%s %s has unsupported suffix .%s: %q", c.goarch, baseOp, suffix, ins.Raw)
		}
	}
	if baseOp != "VCVTSS2SD" && baseOp != "VCVTSD2SS" {
		return false, false, nil
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects src, upper Xsrc, [K mask,] Xdst: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if !c.isGoEVEXVectorRegister(ins.Args[1], 16) {
		return true, false, fmt.Errorf("%s %s upper source must be a Go 1.27 X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(destination, 16) {
		return true, false, fmt.Errorf("%s %s destination must be a Go 1.27 X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoEVEXVectorRegister(ins.Args[0], 16) {
			return true, false, fmt.Errorf("%s %s register source must be a Go 1.27 X register: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s source must be an X register or memory operand: %q", c.goarch, baseOp, ins.Raw)
	}
	if (sae || rounding != "") && ins.Args[0].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s embedded rounding/SAE requires a register source: %q", c.goarch, baseOp, ins.Raw)
	}
	var converted string
	var err error
	if baseOp == "VCVTSS2SD" {
		src, e := c.evalF32(ins.Args[0])
		if e != nil {
			return true, false, e
		}
		converted = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", converted, src)
	} else {
		src, e := c.evalF64(ins.Args[0])
		if e != nil {
			return true, false, e
		}
		converted = c.emitRoundedF64ToF32(src, rounding)
	}
	upperBytes, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	mask := ""
	if masked {
		mask, err = c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
	}
	if baseOp == "VCVTSS2SD" {
		upperWords := c.bitcastVectorBytesToIntegerLanes(16, 2, 64, upperBytes)
		lowBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %%%s to i64\n", lowBits, converted)
		return true, false, c.storeVectorScalarRegister(destination.Reg, 64, "%"+lowBits, upperWords, mask, zeroing)
	}

	upperWords := c.bitcastVectorBytesToIntegerLanes(16, 4, 32, upperBytes)
	lowBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast float %%%s to i32\n", lowBits, converted)
	return true, false, c.storeVectorScalarRegister(destination.Reg, 32, "%"+lowBits, upperWords, mask, zeroing)
}

// emitRoundedF64ToF32 implements EVEX embedded rounding independently of the
// host floating-point environment. LLVM's scalar constrained fptrunc may lower
// to the ambient MXCSR mode on targets without AVX-512, so compute the nearest
// result first and step one IEEE-754 float toward the requested direction only
// when extending it back to double proves that adjustment is necessary.
func (c *amd64Ctx) emitRoundedF64ToF32(source, rounding string) string {
	nearest := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", nearest, source)
	if rounding == "" || rounding == "RN_SAE" {
		return nearest
	}
	expanded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fpext float %%%s to double\n", expanded, nearest)
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast float %%%s to i32\n", bits, nearest)
	negativeBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 0\n", negativeBits, bits)
	incremented := c.newTmp()
	decremented := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, 1\n", incremented, bits)
	fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", decremented, bits)
	nextUpBits := c.newTmp()
	nextDownBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %%%s\n", nextUpBits, negativeBits, decremented, incremented)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %%%s\n", nextDownBits, negativeBits, incremented, decremented)
	nextUp := c.newTmp()
	nextDown := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", nextUp, nextUpBits)
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", nextDown, nextDownBits)
	needsUp := c.newTmp()
	needsDown := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp olt double %%%s, %s\n", needsUp, expanded, source)
	fmt.Fprintf(c.b, "  %%%s = fcmp ogt double %%%s, %s\n", needsDown, expanded, source)
	upResult := c.newTmp()
	downResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, float %%%s, float %%%s\n", upResult, needsUp, nextUp, nearest)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, float %%%s, float %%%s\n", downResult, needsDown, nextDown, nearest)
	switch rounding {
	case "RD_SAE":
		return downResult
	case "RU_SAE":
		return upResult
	case "RZ_SAE":
		negativeSource := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp olt double %s, 0.000000e+00\n", negativeSource, source)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, float %%%s, float %%%s\n", result, negativeSource, upResult, downResult)
		return result
	default:
		return nearest
	}
}

func (c *amd64Ctx) evalF32(op Operand) (string, error) {
	switch op.Kind {
	case OpReg:
		if _, ok := amd64ParseXReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected X register for f32 operand, got %s", op.String())
		}
		return c.loadXLowF32(op.Reg)
	case OpImm:
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %d to i32\n", bits, op.Imm)
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", value, bits)
		return "%" + value, nil
	case OpFP:
		return c.evalFPToF32(op.FPOffset)
	case OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load float, %s %s, align 1\n", value, ptrType, p)
		return "%" + value, nil
	case OpSym:
		p, err := c.ptrFromSB(op.Sym)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load float, ptr %s, align 1\n", value, p)
		return "%" + value, nil
	default:
		return "", fmt.Errorf("amd64: unsupported f32 operand %s", op.String())
	}
}

func (c *amd64Ctx) evalFPToF32(off int64) (string, error) {
	slot, ok := c.fpParam(off)
	if !ok {
		return "", fmt.Errorf("unsupported FP read slot for f32: +%d(FP)", off)
	}
	ty := slot.Type
	arg, err := c.loadFPParamValue(slot)
	if err != nil {
		return "", fmt.Errorf("FP read slot for f32 at +%d(FP): %w", off, err)
	}
	switch ty {
	case LLVMType("float"):
		return arg, nil
	case I32:
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to float\n", value, arg)
		return "%" + value, nil
	default:
		return "", fmt.Errorf("FP read unsupported type %q for f32 at +%d(FP)", ty, off)
	}
}

func (c *amd64Ctx) evalF64(op Operand) (string, error) {
	switch op.Kind {
	case OpReg:
		if _, ok := amd64ParseXReg(op.Reg); !ok {
			return "", fmt.Errorf("amd64: expected X register for f64 operand, got %s", op.String())
		}
		return c.loadXLowF64(op.Reg)
	case OpImm:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %d to double\n", t, op.Imm)
		return "%" + t, nil
	case OpFP:
		return c.evalFPToF64(op.FPOffset)
	case OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		ld := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load double, %s %s, align 1\n", ld, ptrType, p)
		return "%" + ld, nil
	case OpSym:
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
	ty := slot.Type
	arg, err := c.loadFPParamValue(slot)
	if err != nil {
		return "", fmt.Errorf("FP read slot for f64 at +%d(FP): %w", off, err)
	}
	switch ty {
	case LLVMType("double"):
		return arg, nil
	case LLVMType("float"):
		next, ok := c.fpParam(off + 4)
		if !ok || next.Type != LLVMType("float") {
			return "", fmt.Errorf("FP read at +%d(FP) cannot form MOVSD's 64-bit memory operand", off)
		}
		low, err := c.evalFPToI64(off)
		if err != nil {
			return "", err
		}
		high, err := c.evalFPToI64(off + 4)
		if err != nil {
			return "", err
		}
		shifted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 32\n", shifted, high)
		packed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %s, %%%s\n", packed, low, shifted)
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to double\n", value, packed)
		return "%" + value, nil
	case I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, arg)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("FP read unsupported type %q for f64 at +%d(FP)", ty, off)
	}
}
