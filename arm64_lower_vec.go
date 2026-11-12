package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// Go's registerExtension reads one scanner.Int, then ParseInt(base 10, 16).
// Whitespace is lexical; signs, expressions, nondecimal literals and unresolved
// names are not lane indices. Instruction families still enforce their own
// suffix/destination-selected physical bounds after this shared token check.
func arm64ParseLaneDecimalToken(source string) (int, bool) {
	text := strings.TrimSpace(source)
	if text == "" {
		return 0, false
	}
	for i := range text {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	index, err := strconv.ParseInt(text, 10, 16)
	return int(index), err == nil
}

func arm64ParseVRegLane(r Reg) (kind byte, lane int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	dot := strings.IndexByte(s, '.')
	if dot < 0 || dot+1 >= len(s) {
		return 0, 0, false
	}
	rest := s[dot+1:] // e.g. S[0], D[01]
	if len(rest) < 4 || rest[1] != '[' || rest[len(rest)-1] != ']' {
		return 0, 0, false
	}
	k := rest[0]
	n, valid := arm64ParseLaneDecimalToken(rest[2 : len(rest)-1])
	if !valid {
		return 0, 0, false
	}
	max := -1
	switch k {
	case 'B':
		max = 16
	case 'H':
		max = 8
	case 'S':
		max = 4
	case 'D':
		max = 2
	default:
		return 0, 0, false
	}
	if n < 0 || n >= max {
		return 0, 0, false
	}
	return k, n, true
}

// Vector/NEON lowering for a small subset used by stdlib asm.
// We model V0..V31 as <16 x i8>.
func (c *arm64Ctx) lowerVec(op Op, postInc bool, ins Instr) (ok bool, terminated bool, err error) {
	// Validate source/dispatcher agreement before any other vector helper
	// can emit IR for a conflicting opcode.
	if ok, terminated, err := c.lowerARM64StructureLoadStore(op, postInc, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorMove(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64SignedLaneExtract(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64WideningAddSubtract(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorAbsDiff(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFloatImmediate(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorConstant(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorDuplicate(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64SHA3(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64AES(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64SHA(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64FloatPair(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorBitReverse(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorCountBits(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorReverse(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorTableLookup(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64PolynomialMultiply(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorWideningMultiply(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFloatNarrow(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFloatWiden(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorLogical(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorIntegerCompare(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorIntegerMinMax(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorIntegerMinMaxAcross(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorAddLongAcross(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorIntegerAbsNeg(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorIntegerNarrow(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorSaturatingShiftNarrow(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorShiftNarrow(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorShiftLeft(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorVariableShift(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorSaturatingShift(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorShiftRight(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorShiftInsert(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFloatUnary(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFloatMinMaxAcross(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFloatArithmetic(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFloatCompare(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorHalvingAdd(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorSaturatingArithmetic(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorIntegerMultiply(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64AddAcross(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorIntegerAddSub(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorFMA(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorExtract(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64VectorPermute(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64WideningShift(op, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "FMOVQ":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 FMOVQ expects 2 operands: %q", ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		preInc := strings.Contains(strings.ToUpper(string(ins.Op)), ".W")
		memory, data := src, dst
		if dst.Kind == OpSym {
			memory, data = dst, src
		}
		if string(ins.Op) == "FMOVQ" && memory.Kind == OpSym && data.Kind == OpReg &&
			!strings.HasPrefix(strings.TrimSpace(memory.Sym), "$") {
			if _, valid := arm64ParseFReg(data.Reg); valid && sourceSymbolOffsetNeedsContext(memory.Sym) {
				return true, false, fmt.Errorf("%w: arm64 FMOVQ symbol displacement requires generated assembler constants: %q", ErrProbeNeedsContext, ins.Raw)
			}
		}
		switch {
		case (src.Kind == OpFP || src.Kind == OpMem || src.Kind == OpSym) && dst.Kind == OpReg:
			if _, ok := arm64ParseFReg(dst.Reg); !ok {
				return true, false, fmt.Errorf("arm64 FMOVQ expects an F register destination: %q", ins.Raw)
			}
			if src.Kind == OpFP {
				if preInc || postInc {
					return true, false, fmt.Errorf("arm64 FMOVQ .P/.W requires register memory: %q", ins.Raw)
				}
				value, err := c.loadFMOVQFrame(src.FPOffset)
				if err != nil {
					return true, false, err
				}
				return true, false, c.storeVReg(dst.Reg, value)
			}
			ptr, base, inc, update, err := c.arm64VectorMemoryPointer(src, preInc, postInc)
			if err != nil {
				return true, false, err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", value, ptr)
			if err := c.storeVReg(dst.Reg, "%"+value); err != nil {
				return true, false, err
			}
			if update {
				if err := c.updatePostInc(base, inc); err != nil {
					return true, false, err
				}
			}
			return true, false, nil
		case src.Kind == OpReg && (dst.Kind == OpFP || dst.Kind == OpMem || dst.Kind == OpSym):
			if _, ok := arm64ParseFReg(src.Reg); !ok {
				return true, false, fmt.Errorf("arm64 FMOVQ expects an F register source: %q", ins.Raw)
			}
			value, err := c.loadVReg(src.Reg)
			if err != nil {
				return true, false, err
			}
			if dst.Kind == OpFP {
				if preInc || postInc {
					return true, false, fmt.Errorf("arm64 FMOVQ .P/.W requires register memory: %q", ins.Raw)
				}
				return true, false, c.storeFMOVQFrame(dst.FPOffset, value)
			}
			ptr, base, inc, update, err := c.arm64VectorMemoryPointer(dst, preInc, postInc)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", value, ptr)
			if update {
				if err := c.updatePostInc(base, inc); err != nil {
					return true, false, err
				}
			}
			return true, false, nil
		default:
			return true, false, fmt.Errorf("arm64 FMOVQ expects memory and F register operands: %q", ins.Raw)
		}

	case "VMOVI":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VMOVI expects $imm, Vreg.B8/B16: %q", ins.Raw)
		}
		imm := ins.Args[0].Imm
		if imm < 0 || imm > 255 {
			return true, false, fmt.Errorf("arm64 VMOVI byte immediate out of range: %q", ins.Raw)
		}
		dst := strings.ToUpper(string(ins.Args[1].Reg))
		activeLanes := 16
		switch {
		case strings.Contains(dst, ".B8"):
			activeLanes = 8
		case strings.Contains(dst, ".B16"):
		default:
			return true, false, fmt.Errorf("arm64 VMOVI unsupported vector arrangement: %q", ins.Raw)
		}
		elems := make([]string, 16)
		for i := range elems {
			value := int64(0)
			if i < activeLanes {
				value = imm
			}
			elems[i] = fmt.Sprintf("i8 %d", value)
		}
		return true, false, c.storeVReg(ins.Args[1].Reg, "<"+strings.Join(elems, ", ")+">")

	case "VEOR":
		// VEOR Va, Vb, Vd
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VEOR expects reg, reg, reg: %q", ins.Raw)
		}
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", t, a, b)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+t)

	case "VORR":
		// VORR Va, Vb, Vd
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VORR expects reg, reg, reg: %q", ins.Raw)
		}
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or <16 x i8> %s, %s\n", t, a, b)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+t)

	case "VCMEQ":
		// VCMEQ Va.B16, Vb.B16, Vd.B16 (or D2 lane-wide compare)
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VCMEQ expects reg, reg, reg: %q", ins.Raw)
		}
		s0 := strings.ToUpper(string(ins.Args[0].Reg))
		s1 := strings.ToUpper(string(ins.Args[1].Reg))
		if strings.Contains(s0, ".D2") || strings.Contains(s1, ".D2") {
			a, err := c.loadVReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			b, err := c.loadVReg(ins.Args[1].Reg)
			if err != nil {
				return true, false, err
			}
			ab := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", ab, a)
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bb, b)
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq <2 x i64> %%%s, %%%s\n", cmp, ab, bb)
			sext := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext <2 x i1> %%%s to <2 x i64>\n", sext, cmp)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, sext)
			return true, false, c.storeVReg(ins.Args[2].Reg, "%"+out)
		}

		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq <16 x i8> %s, %s\n", cmp, a, b)
		sext := c.newTmp()
		// sext i1 -> i8 yields 0 or -1 (0xFF), which matches CMEQ's all-ones convention.
		fmt.Fprintf(c.b, "  %%%s = sext <16 x i1> %%%s to <16 x i8>\n", sext, cmp)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+sext)

	case "VAND":
		// VAND Va, Vb, Vd
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VAND expects reg, reg, reg: %q", ins.Raw)
		}
		a, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and <16 x i8> %s, %s\n", t, a, b)
		return true, false, c.storeVReg(ins.Args[2].Reg, "%"+t)

	case "VADDP":
		return true, false, c.lowerARM64VectorADDP(ins)

	case "VADD":
		// VADD Vs, Vd (2-operand accumulate in D[0]) or VADD Va, Vb, Vd (S4 vector add).
		if len(ins.Args) == 3 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpReg && ins.Args[2].Kind == OpReg {
			a, err := c.loadVReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			b, err := c.loadVReg(ins.Args[1].Reg)
			if err != nil {
				return true, false, err
			}
			ab := c.newTmp()
			bb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", ab, a)
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bb, b)
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, %%%s\n", sum, ab, bb)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, sum)
			return true, false, c.storeVReg(ins.Args[2].Reg, "%"+out)
		}

		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VADD expects reg, reg or reg, reg, reg: %q", ins.Raw)
		}
		sv, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dv, err := c.loadVReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		sbc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", sbc, sv)
		dbc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", dbc, dv)
		se := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", se, sbc)
		de := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", de, dbc)
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", add, de, se)
		vec := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %%%s, i32 0\n", vec, add)
		vec2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 0, i32 1\n", vec2, vec)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, vec2)
		return true, false, c.storeVReg(ins.Args[1].Reg, "%"+bc)
	}
	return false, false, nil
}

func (c *arm64Ctx) arm64VectorMemoryPointer(op Operand, preInc, postInc bool) (ptr string, base Reg, inc int64, update bool, err error) {
	if preInc && postInc {
		return "", "", 0, false, fmt.Errorf("arm64: memory operand cannot be both pre- and post-indexed")
	}
	if op.Kind == OpSym {
		if preInc || postInc {
			return "", "", 0, false, fmt.Errorf("arm64: symbol operand cannot be pre- or post-indexed")
		}
		ptr, err := c.ptrFromSB(op.Sym)
		return ptr, "", 0, false, err
	}
	if op.Kind != OpMem {
		return "", "", 0, false, fmt.Errorf("arm64: expected memory operand")
	}
	if err := validateARM64MemoryIndex(op.Mem, 128); err != nil {
		return "", "", 0, false, err
	}
	addr, base, inc, err := c.addrI64(op.Mem, postInc)
	if err != nil {
		return "", "", 0, false, err
	}
	if preInc {
		if err := c.storeReg(base, addr); err != nil {
			return "", "", 0, false, err
		}
	}
	pt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
	return "%" + pt, base, inc, postInc, nil
}

func (c *arm64Ctx) broadcastI8ToV16(v8 string) (string, error) {
	ins := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i8> undef, i8 %s, i32 0\n", ins, v8)
	shuf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> poison, <16 x i32> zeroinitializer\n", shuf, ins)
	return "%" + shuf, nil
}

func (c *arm64Ctx) broadcastI32ToV16(v32 string) (string, error) {
	ins := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> undef, i32 %s, i32 0\n", ins, v32)
	shuf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i32> %%%s, <4 x i32> poison, <4 x i32> zeroinitializer\n", shuf, ins)
	bc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc, shuf)
	return "%" + bc, nil
}
