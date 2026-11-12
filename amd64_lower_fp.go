package plan9asm

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func (c *amd64Ctx) lowerFP(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if known, term, err := c.lowerSqrt(op, ins); known {
		return known, term, err
	}
	if known, term, err := c.lowerLegacyPackedMove(op, ins); known {
		return known, term, err
	}
	if ok, term, err := c.lowerSignedIntegerScalarFloat(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerFloatArithmetic(op, ins, ""); ok {
		return ok, term, err
	}
	if spec, recognized := amd64ScalarVectorMoveSpecs[op]; recognized && spec.legacy {
		if _, _, err := amd64ScalarVectorMoveProperties(ins, c.goarch); err != nil {
			return true, false, err
		}
	}
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
		if _, recognized := amd64BinaryFloatingSpecs[Op(base)]; recognized {
			return c.lowerBinaryFloating(op, ins)
		}
		if _, recognized := amd64FMA3Specs[Op(base)]; recognized {
			return c.lowerFMA3(op, ins)
		}
		if _, recognized := x86PackedLogicalSpecs[Op(base)]; recognized {
			return c.lowerPackedFloatingLogical(op, ins)
		}
		if _, known := x86ScalarPrecisionSpecs[Op(base)]; known {
			return c.lowerScalarPrecisionConvert(op, ins)
		}
	}
	switch op {
	case "MOVSS", "MOVSD", "MOVAPD", "MOVUPD",
		"MOVLHPS", "MOVHLPS", "MOVLPS", "MOVHPS", "MOVLPD", "MOVHPD",
		"VMOVLPS", "VMOVHPS", "VMOVLPD", "VMOVHPD", "SHUFPD", "UNPCKLPS", "UNPCKHPD",
		"COMISS", "UCOMISS", "COMISD", "UCOMISD", "CMPSD",
		"CVTSL2SD", "CVTSQ2SD":
		// handled below
	default:
		return false, false, nil
	}

	switch op {
	case "MOVSS":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 MOVSS expects src, dst: %q", ins.Raw)
		}
		v, err := c.loadLegacyScalarMoveSource(ins, 32)
		if err != nil {
			return true, false, err
		}
		switch ins.Args[1].Kind {
		case OpReg:
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
				return true, false, fmt.Errorf("amd64 MOVSS expects X-reg destination: %q", ins.Raw)
			}
			return true, false, c.storeLegacyScalarMoveRegister(ins.Args[1].Reg, v, 32, ins.Args[0].Kind == OpReg)
		case OpFP:
			return true, false, c.storeScalarFPFloat(ins.Args[1].FPOffset, 32, v)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store volatile float %s, ptr %s, align 1\n", v, c.ptrFromAddrI64(addr))
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
		v, err := c.loadLegacyScalarMoveSource(ins, 64)
		if err != nil {
			return true, false, err
		}
		switch ins.Args[1].Kind {
		case OpReg:
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
				return true, false, fmt.Errorf("amd64 MOVSD expects X-reg destination: %q", ins.Raw)
			}
			return true, false, c.storeLegacyScalarMoveRegister(ins.Args[1].Reg, v, 64, ins.Args[0].Kind == OpReg)
		case OpFP:
			return true, false, c.storeScalarFPFloat(ins.Args[1].FPOffset, 64, v)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store volatile double %s, ptr %s, align 1\n", v, p)
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

	case "COMISS", "UCOMISS", "COMISD", "UCOMISD":
		return c.lowerVectorScalarFlagCompare(op, ins)

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
		// ABI0 fields need not be two contiguous uint64 values. Assemble
		// every declared byte, including adjacent float32 and narrow fields.
		return c.loadFPVectorBytes(op.FPOffset, 16)
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
		return c.storeFPVectorBytes(op.FPOffset, 16, value, "")
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

// Legacy scalar moves preserve bits above 127 in every physical alias. The
// source class separately determines whether the upper XMM lanes survive.
// Do not use this helper for VEX/EVEX writes, which zero their wider views.
func (c *amd64Ctx) storeLegacyScalarMoveRegister(r Reg, value string, bits int, preserve bool) error {
	var store func(Reg, string) error
	switch bits {
	case 32:
		store = c.storeXLowF32ClearingUpper
		if preserve {
			store = c.storeXLowF32
		}
	case 64:
		store = c.storeXLowF64ClearingUpper
		if preserve {
			store = c.storeXLowF64
		}
	default:
		return fmt.Errorf("invalid legacy scalar move width %d", bits)
	}
	if err := store(r, value); err != nil {
		return err
	}
	xmm, err := c.loadX(r)
	if err != nil {
		return err
	}
	return c.storeLegacyXViews(r, xmm)
}

func (c *amd64Ctx) storeXLowF64ClearingUpper(r Reg, v string) error {
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", bits, v)
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %%%s, i32 0\n", inserted, bits)
	back := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", back, inserted)
	return c.storeX(r, "%"+back)
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
	high         bool
	vector       bool
	registerOnly bool
}

// The memory halves use yxmov/_yvmovhpd. The explicit register-only aliases
// add yxr/_yvmovhlps while sharing the selected source/base/output halves.
// VEX/EVEX memory halves still accept only m64 loads or stores.
var amd64MoveHalfSpecs = map[Op]amd64MoveHalfSpec{
	"MOVHLPS":  {registerOnly: true},
	"MOVLHPS":  {high: true, registerOnly: true},
	"VMOVHLPS": {vector: true, registerOnly: true},
	"VMOVLHPS": {high: true, vector: true, registerOnly: true},
	"MOVLPS":   {},
	"MOVHPS":   {high: true},
	"MOVLPD":   {},
	"MOVHPD":   {high: true},
	"VMOVLPS":  {vector: true},
	"VMOVHPS":  {high: true, vector: true},
	"VMOVLPD":  {vector: true},
	"VMOVHPD":  {high: true, vector: true},
}

func (c *amd64Ctx) lowerMOVHalf(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86MoveHalfProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.undocumentedPDRegister {
		return true, false, fmt.Errorf("%w: %s's Go register encoding lacks documented Intel PD semantics", ErrProbeNeedsContext, op)
	}
	return true, false, c.emitMoveHalf(form, ins)
}

func (c *amd64Ctx) emitMoveHalf(form x86MoveHalfForm, ins Instr) error {
	if form.store {
		source, err := c.loadXAsI64x2(ins.Args[form.source].Reg)
		if err != nil {
			return err
		}
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %s, i32 %d\n", bits, source, form.sourceLane)
		return c.storePackedScalarExtractMemory(ins.Args[form.destination], I64, "%"+bits)
	}
	var bits string
	if form.memory >= 0 {
		var err error
		if source := ins.Args[form.source]; source.Kind == OpFP {
			bits, err = c.loadScalarLaneFPBits(source.FPOffset, 64)
		} else {
			bits, err = c.evalSizedNativeGPSource(source, I64, ins.x86AddressBits)
		}
		if err != nil {
			return err
		}
	} else {
		source, err := c.loadXAsI64x2(ins.Args[form.source].Reg)
		if err != nil {
			return err
		}
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %s, i32 %d\n", extracted, source, form.sourceLane)
		bits = "%" + extracted
	}
	base, err := c.loadXAsI64x2(ins.Args[form.base].Reg)
	if err != nil {
		return err
	}
	inserted, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %s, i64 %s, i32 %d\n", inserted, base, bits, form.outputLane)
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, inserted)
	if form.spec.vector {
		return c.storePackedMoveOperand(ins.Args[form.destination], 16, "%"+bytes)
	}
	return c.storeLegacyXViews(ins.Args[form.destination].Reg, "%"+bytes)
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
		if op.ImmIsFloat {
			// The parser retains the original float64 constant. Go's
			// Float32Sym rounds its numeric value, not its low 32 bits.
			rounded := math.Float32bits(float32(math.Float64frombits(uint64(op.Imm))))
			fmt.Fprintf(c.b, "  %%%s = bitcast i32 %d to float\n", bits, rounded)
			return "%" + bits, nil
		}
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
	bits, err := c.loadScalarFPBits(off, 32)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to float\n", value, bits)
	return "%" + value, nil
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
	bits, err := c.loadScalarFPBits(off, 64)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", value, bits)
	return "%" + value, nil
}
