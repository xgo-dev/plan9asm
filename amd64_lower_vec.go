package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerVec(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if raw := string(op); strings.Contains(raw, ".") {
		if i := strings.IndexByte(raw, '.'); i >= 0 {
			op = Op(raw[:i])
		}
	}
	switch op {
	case "MOVOU", "MOVOA", "MOVUPS", "MOVAPS", "MOVO", "MOVQ", "MOVL", "MOVD",
		"VMOVDQU", "VMOVDQA", "VMOVNTDQ", "VMOVDQU64", "VMOVDQA64", "VMOVAPS", "VMOVAPD",
		"VPCMPEQB", "VPMOVMSKB", "VZEROUPPER", "VZEROALL", "VPBROADCASTB", "VPAND", "VPXOR", "VPOR", "VPADDD", "VPADDQ", "VPTEST",
		"VPANDQ", "VPXORQ", "VPORQ", "VPCLMULQDQ", "VPTERNLOGD", "VEXTRACTF32X4",
		"VPERMB", "VGF2P8AFFINEQB", "VPERMI2B", "VPCOMPRESSQ", "VPOPCNTB", "VPCMPUQ",
		"VBROADCASTI128", "VBROADCASTF32X2", "VBROADCASTSD", "VXORPD",
		"VPSHUFB", "VPSHUFD", "VPSLLD", "VPSRLD", "VPSRLQ", "VPSLLQ", "VPSRLDQ", "VPSLLDQ",
		"VPALIGNR", "VPERM2I128", "VPERM2F128", "VINSERTI128", "VPBLENDD",
		"PXOR", "PAND", "PANDN", "PADDD", "PADDL", "PSUBL", "PCLMULQDQ", "PCMPEQB", "PCMPEQL", "PMOVMSKB",
		"PSHUFB", "PSRLDQ", "PSLLDQ", "PSRLQ", "PSRLL", "PSLLL", "PSRAL", "PEXTRD", "PEXTRB", "PEXTRQ",
		"PINSRQ", "PINSRD", "PINSRB", "PINSRW", "PALIGNR", "PUNPCKLBW", "PSHUFL", "PSHUFD", "PSHUFHW", "SHUFPS",
		"PBLENDW", "PADDQ", "KMOVB", "KMOVW", "KMOVQ", "KXORQ",
		"SHA1NEXTE", "SHA1MSG1", "SHA1MSG2", "SHA1RNDS4", "SHA256MSG1", "SHA256MSG2", "SHA256RNDS2",
		"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC", "AESKEYGENASSIST", "PCMPESTRI":
		// ok
	default:
		return false, false, nil
	}

	// MOVL src, Xn (seed vector low 32 bits).
	if op == "MOVL" && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); ok {
			var v64 string
			var err error
			switch ins.Args[0].Kind {
			case OpImm, OpReg, OpFP, OpMem, OpSym:
				v64, err = c.evalI64(ins.Args[0])
			default:
				return true, false, fmt.Errorf("amd64 MOVL to X reg unsupported src: %q", ins.Raw)
			}
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
			// Build <4 x i32> { crc, 0, 0, 0 } then bitcast to <16 x i8>.
			v0 := "%" + tr
			tvec := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> zeroinitializer, i32 %s, i32 0\n", tvec, v0)
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc, tvec)
			return true, false, c.storeX(ins.Args[1].Reg, "%"+bc)
		}
	}

	// MOVD reg, Xn (seed vector with low 32-bit value)
	if op == "MOVD" && len(ins.Args) == 2 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpReg {
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); ok {
			v64, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
			// Build <4 x i32> { v, 0, 0, 0 } then bitcast to <16 x i8>.
			v0 := "%" + tr
			tvec := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> zeroinitializer, i32 %s, i32 0\n", tvec, v0)
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc, tvec)
			return true, false, c.storeX(ins.Args[1].Reg, "%"+bc)
		}
	}

	if op == "VZEROUPPER" {
		// No-op in LLVM IR. Kept for completeness.
		return true, false, nil
	}
	if op == "VZEROALL" {
		return true, false, nil
	}

	if op == "VMOVDQA" {
		op = "VMOVDQU"
	}
	if op == "VMOVDQA64" {
		op = "VMOVDQU64"
	}
	if op == "VPERM2F128" {
		op = "VPERM2I128"
	}
	if op == "VMOVAPS" || op == "VMOVAPD" {
		if len(ins.Args) == 2 {
			if (ins.Args[0].Kind == OpReg && isAMD64ZReg(ins.Args[0].Reg)) ||
				(ins.Args[1].Kind == OpReg && isAMD64ZReg(ins.Args[1].Reg)) {
				op = "VMOVDQU64"
			} else {
				op = "VMOVDQU"
			}
		}
	}
	if op == "VPXORQ" || op == "VPANDQ" || op == "VPORQ" {
		if len(ins.Args) == 3 && ins.Args[2].Kind == OpReg && !isAMD64ZReg(ins.Args[2].Reg) {
			switch op {
			case "VPXORQ":
				op = "VPXOR"
			case "VPANDQ":
				op = "VPAND"
			case "VPORQ":
				op = "VPOR"
			}
		}
	}

	// MOVUPS/MOVAPS/MOVO are aliases for unaligned/aligned 128-bit xmm moves.
	if op == "MOVUPS" || op == "MOVAPS" || op == "MOVO" {
		op = "MOVOU"
	}

	// MOVQ src, Xn (load low 64 bits into Xn)
	if op == "MOVQ" && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); ok {
			var low string
			switch ins.Args[0].Kind {
			case OpImm:
				low = fmt.Sprintf("%d", ins.Args[0].Imm)
			case OpReg:
				v, err := c.loadReg(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				low = v
			case OpFP:
				v, err := c.evalFPToI64(ins.Args[0].FPOffset)
				if err != nil {
					return true, false, err
				}
				low = v
			case OpMem:
				addr, err := c.addrFromMem(ins.Args[0].Mem)
				if err != nil {
					return true, false, err
				}
				p := c.ptrFromAddrI64(addr)
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
				low = "%" + ld
			case OpSym:
				p, err := c.ptrFromSB(ins.Args[0].Sym)
				if err != nil {
					return true, false, err
				}
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
				low = "%" + ld
			default:
				return true, false, fmt.Errorf("amd64 MOVQ to X reg unsupported src: %q", ins.Raw)
			}
			// Build <2 x i64> { low, 0 }.
			ins0 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %s, i32 0\n", ins0, low)
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, ins0)
			return true, false, c.storeX(ins.Args[1].Reg, "%"+bc)
		}
	}

	// MOVQ Xn, dst (extract low 64 bits from Xn).
	if op == "MOVQ" && len(ins.Args) == 2 && ins.Args[0].Kind == OpReg {
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); ok {
			xv, err := c.loadX(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			bc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, xv)
			lo := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", lo, bc)
			switch ins.Args[1].Kind {
			case OpReg:
				return true, false, c.storeReg(ins.Args[1].Reg, "%"+lo)
			case OpMem:
				addr, err := c.addrFromMem(ins.Args[1].Mem)
				if err != nil {
					return true, false, err
				}
				p := c.ptrFromAddrI64(addr)
				fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s, align 1\n", lo, p)
				return true, false, nil
			default:
				return true, false, fmt.Errorf("amd64 MOVQ from X reg unsupported dst: %q", ins.Raw)
			}
		}
	}

	switch op {
	case "KXORQ":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 KXORQ expects Ksrc1, Ksrc2, Kdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseKReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseKReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseKReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadK(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		x := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", x, a, b)
		return true, false, c.storeK(ins.Args[2].Reg, "%"+x)

	case "KMOVB", "KMOVW", "KMOVQ":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects 2 operands: %q", op, ins.Raw)
		}
		bits := 64
		loadTy := "i64"
		switch op {
		case "KMOVB":
			bits, loadTy = 8, "i8"
		case "KMOVW":
			bits, loadTy = 16, "i16"
		}
		maskValue := func(v string) string {
			if bits == 64 {
				return v
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", t, v, (uint64(1)<<bits)-1)
			return "%" + t
		}
		loadToI64 := func(opnd Operand) (string, error) {
			switch opnd.Kind {
			case OpReg:
				if _, ok := amd64ParseKReg(opnd.Reg); ok {
					v, err := c.loadK(opnd.Reg)
					if err != nil {
						return "", err
					}
					return maskValue(v), nil
				}
				v, err := c.loadReg(opnd.Reg)
				if err != nil {
					return "", err
				}
				return maskValue(v), nil
			case OpMem:
				addr, err := c.addrFromMem(opnd.Mem)
				if err != nil {
					return "", err
				}
				p := c.ptrFromAddrI64(addr)
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, loadTy, p)
				if bits == 64 {
					return "%" + ld, nil
				}
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", z, loadTy, ld)
				return "%" + z, nil
			default:
				return "", fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
			}
		}
		storeFromI64 := func(opnd Operand, v string) error {
			switch opnd.Kind {
			case OpReg:
				if _, ok := amd64ParseKReg(opnd.Reg); ok {
					return c.storeK(opnd.Reg, maskValue(v))
				}
				if bits == 64 {
					return c.storeReg(opnd.Reg, v)
				}
				return c.storeReg(opnd.Reg, maskValue(v))
			case OpMem:
				addr, err := c.addrFromMem(opnd.Mem)
				if err != nil {
					return err
				}
				p := c.ptrFromAddrI64(addr)
				if bits == 64 {
					fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", v, p)
					return nil
				}
				tr := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v, loadTy)
				fmt.Fprintf(c.b, "  store %s %%%s, ptr %s, align 1\n", loadTy, tr, p)
				return nil
			default:
				return fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
			}
		}
		v, err := loadToI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		return true, false, storeFromI64(ins.Args[1], v)

	case "VPERMB":
		if len(ins.Args) != 3 && len(ins.Args) != 4 {
			return true, false, fmt.Errorf("amd64 VPERMB expects idx, src, dst or idx, src, Kmask, dst: %q", ins.Raw)
		}
		dstIdx := 2
		if len(ins.Args) == 4 {
			dstIdx = 3
		}
		if ins.Args[dstIdx].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPERMB expects Z destination register: %q", ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[dstIdx].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadZVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		if len(ins.Args) == 4 {
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 VPERMB masked form expects K mask register: %q", ins.Raw)
			}
			if _, ok := amd64ParseKReg(ins.Args[2].Reg); !ok {
				return false, false, nil
			}
			maskv, err := c.loadK(ins.Args[2].Reg)
			if err != nil {
				return true, false, err
			}
			src = amd64SelectZByAnyMask(c, src, maskv)
		}
		return true, false, c.storeZ(ins.Args[dstIdx].Reg, src)

	case "VGF2P8AFFINEQB":
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VGF2P8AFFINEQB expects $imm, mat, src, dst: %q", ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[3].Reg); ok {
			if ins.Args[2].Kind == OpReg {
				if _, ok := amd64ParseZReg(ins.Args[2].Reg); !ok {
					return false, false, nil
				}
			}
			src, err := c.loadZVecOperand(ins.Args[2])
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeZ(ins.Args[3].Reg, src)
		}
		if _, ok := amd64ParseYReg(ins.Args[3].Reg); ok {
			if ins.Args[2].Kind == OpReg {
				if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
					return false, false, nil
				}
			}
			src, err := c.loadYVecOperand(ins.Args[2])
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeY(ins.Args[3].Reg, src)
		}
		return false, false, nil

	case "VPERMI2B":
		if len(ins.Args) != 3 && len(ins.Args) != 4 {
			return true, false, fmt.Errorf("amd64 VPERMI2B expects src1, src2, dst or src1, src2, Kmask, dst: %q", ins.Raw)
		}
		dstIdx := 2
		srcIdx := 1
		if len(ins.Args) == 4 {
			dstIdx = 3
		}
		if ins.Args[dstIdx].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPERMI2B expects Z destination register: %q", ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[dstIdx].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadZVecOperand(ins.Args[srcIdx])
		if err != nil {
			return true, false, err
		}
		if len(ins.Args) == 4 {
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 VPERMI2B masked form expects K mask register: %q", ins.Raw)
			}
			if _, ok := amd64ParseKReg(ins.Args[2].Reg); !ok {
				return false, false, nil
			}
			maskv, err := c.loadK(ins.Args[2].Reg)
			if err != nil {
				return true, false, err
			}
			src = amd64SelectZByAnyMask(c, src, maskv)
		}
		return true, false, c.storeZ(ins.Args[dstIdx].Reg, src)

	case "VPOPCNTB":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPOPCNTB expects src, Zdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadZVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		out := amd64BytePopcountZ(c, src)
		return true, false, c.storeZ(ins.Args[1].Reg, out)

	case "VPCMPUQ":
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPCMPUQ expects $imm, src1, src2, Kdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseKReg(ins.Args[3].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadZVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		b, err := c.loadZVecOperand(ins.Args[2])
		if err != nil {
			return true, false, err
		}
		ab := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <64 x i8> %s to <8 x i64>\n", ab, a)
		bb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <64 x i8> %s to <8 x i64>\n", bb, b)
		cmp := c.newTmp()
		switch ins.Args[0].Imm & 0x7 {
		case 0:
			fmt.Fprintf(c.b, "  %%%s = icmp eq <8 x i64> %%%s, %%%s\n", cmp, ab, bb)
		case 1:
			fmt.Fprintf(c.b, "  %%%s = icmp ult <8 x i64> %%%s, %%%s\n", cmp, ab, bb)
		case 2:
			fmt.Fprintf(c.b, "  %%%s = icmp ule <8 x i64> %%%s, %%%s\n", cmp, ab, bb)
		case 4:
			fmt.Fprintf(c.b, "  %%%s = icmp ne <8 x i64> %%%s, %%%s\n", cmp, ab, bb)
		case 5:
			fmt.Fprintf(c.b, "  %%%s = icmp uge <8 x i64> %%%s, %%%s\n", cmp, ab, bb)
		case 6:
			fmt.Fprintf(c.b, "  %%%s = icmp ugt <8 x i64> %%%s, %%%s\n", cmp, ab, bb)
		default:
			return true, false, fmt.Errorf("amd64 VPCMPUQ only supports imm 0/1/2/4/5/6 for now: %q", ins.Raw)
		}
		maskv := amd64PackI1x8ToI64(c, "%"+cmp)
		return true, false, c.storeK(ins.Args[3].Reg, maskv)

	case "VPCOMPRESSQ":
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPCOMPRESSQ expects Zsrc, Kmask, Zdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseKReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseZReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadZVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		maskv, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		sv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <64 x i8> %s to <8 x i64>\n", sv, src)
		outVec := "zeroinitializer"
		writePos := "0"
		for i := 0; i < 8; i++ {
			bit := amd64MaskBitI1(c, maskv, i)
			lane := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i64> %%%s, i32 %d\n", lane, sv, i)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i64> %s, i64 %%%s, i32 %s\n", inserted, outVec, lane, writePos)
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, <8 x i64> %%%s, <8 x i64> %s\n", selected, bit, inserted, outVec)
			step := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", step, bit)
			nextPos := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", nextPos, writePos, step)
			outVec = "%" + selected
			writePos = "%" + nextPos
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i64> %s to <64 x i8>\n", out, outVec)
		return true, false, c.storeZ(ins.Args[2].Reg, "%"+out)

	case "VPXORQ", "VPANDQ", "VPORQ":
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src1, src2, dstReg: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadZVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		b, err := c.loadZVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		ab := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <64 x i8> %s to <8 x i64>\n", ab, a)
		bb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <64 x i8> %s to <8 x i64>\n", bb, b)
		t := c.newTmp()
		switch op {
		case "VPXORQ":
			fmt.Fprintf(c.b, "  %%%s = xor <8 x i64> %%%s, %%%s\n", t, ab, bb)
		case "VPANDQ":
			fmt.Fprintf(c.b, "  %%%s = and <8 x i64> %%%s, %%%s\n", t, ab, bb)
		case "VPORQ":
			fmt.Fprintf(c.b, "  %%%s = or <8 x i64> %%%s, %%%s\n", t, ab, bb)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i64> %%%s to <64 x i8>\n", out, t)
		return true, false, c.storeZ(ins.Args[2].Reg, "%"+out)

	case "VBROADCASTI128":
		// VBROADCASTI128 Xsrc|mem, Ydst
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VBROADCASTI128 expects Xsrc|mem, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <32 x i32> %s\n", out, src, src, llvmRepeatI8Mask(16, 32))
		return true, false, c.storeY(ins.Args[1].Reg, "%"+out)

	case "VBROADCASTF32X2", "VBROADCASTSD":
		// Both instructions broadcast one 64-bit memory/register value. The
		// former names the value as two f32 lanes; the latter as one f64 lane.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects scalar src, vector dst: %q", op, ins.Raw)
		}
		v64, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		chunk := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <8 x i8>\n", chunk, v64)
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); ok {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i8> %%%s, <8 x i8> %%%s, <32 x i32> %s\n", out, chunk, chunk, llvmRepeatI8Mask(8, 32))
			return true, false, c.storeY(ins.Args[1].Reg, "%"+out)
		}
		if _, ok := amd64ParseZReg(ins.Args[1].Reg); ok {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i8> %%%s, <8 x i8> %%%s, <64 x i32> %s\n", out, chunk, chunk, llvmRepeatI8Mask(8, 64))
			return true, false, c.storeZ(ins.Args[1].Reg, "%"+out)
		}
		return false, false, nil

	case "VXORPD":
		// VXORPD src1, src2, dst; this is a bitwise operation despite the
		// floating-point mnemonic, so byte-vector xor preserves all bits.
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VXORPD expects src1, src2, dst: %q", ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[2].Reg); ok {
			a, err := c.loadZVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadZVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <64 x i8> %s, %s\n", t, a, b)
			return true, false, c.storeZ(ins.Args[2].Reg, "%"+t)
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); ok {
			a, err := c.loadYVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadYVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <32 x i8> %s, %s\n", t, a, b)
			return true, false, c.storeY(ins.Args[2].Reg, "%"+t)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); ok {
			a, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadXVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", t, a, b)
			return true, false, c.storeX(ins.Args[2].Reg, "%"+t)
		}
		return false, false, nil

	case "VPXOR", "VPOR", "VPADDD", "VPADDQ":
		// V* three-operand op; support both X and Y destinations.
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src1, src2, dstReg: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); ok {
			a, err := c.loadYVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadYVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			switch op {
			case "VPXOR":
				fmt.Fprintf(c.b, "  %%%s = xor <32 x i8> %s, %s\n", t, a, b)
			case "VPOR":
				fmt.Fprintf(c.b, "  %%%s = or <32 x i8> %s, %s\n", t, a, b)
			case "VPADDD":
				ab := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <8 x i32>\n", ab, a)
				bb := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <8 x i32>\n", bb, b)
				add := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add <8 x i32> %%%s, %%%s\n", add, ab, bb)
				fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i32> %%%s to <32 x i8>\n", t, add)
			case "VPADDQ":
				ab := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", ab, a)
				bb := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", bb, b)
				add := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add <4 x i64> %%%s, %%%s\n", add, ab, bb)
				fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i64> %%%s to <32 x i8>\n", t, add)
			}
			return true, false, c.storeY(ins.Args[2].Reg, "%"+t)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); ok {
			a, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadXVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			switch op {
			case "VPXOR":
				fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", t, a, b)
			case "VPOR":
				fmt.Fprintf(c.b, "  %%%s = or <16 x i8> %s, %s\n", t, a, b)
			case "VPADDD":
				ab := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", ab, a)
				bb := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bb, b)
				add := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, %%%s\n", add, ab, bb)
				fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", t, add)
			case "VPADDQ":
				ab := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", ab, a)
				bb := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bb, b)
				add := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add <2 x i64> %%%s, %%%s\n", add, ab, bb)
				fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", t, add)
			}
			return true, false, c.storeX(ins.Args[2].Reg, "%"+t)
		}
		return false, false, nil

	case "VPSHUFB":
		// VPSHUFB Ymask, Ysrc, Ydst
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPSHUFB expects Ymask, Ysrc, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); ok {
			mask, err := c.loadYVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			src, err := c.loadYVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			// Emulate 256-bit PSHUFB by lane-splitting into two 128-bit shuffles.
			srcLo := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", srcLo, src, llvmI32RangeMask(0, 16))
			srcHi := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", srcHi, src, llvmI32RangeMask(16, 16))
			maskLo := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", maskLo, mask, llvmI32RangeMask(0, 16))
			maskHi := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", maskHi, mask, llvmI32RangeMask(16, 16))
			outLo := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %%%s, <16 x i8> %%%s)\n", outLo, srcLo, maskLo)
			outHi := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %%%s, <16 x i8> %%%s)\n", outHi, srcHi, maskHi)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> %%%s, <32 x i32> %s\n", out, outLo, outHi, llvmI32RangeMask(0, 32))
			return true, false, c.storeY(ins.Args[2].Reg, "%"+out)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); ok {
			mask, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			src, err := c.loadXVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %s, <16 x i8> %s)\n", call, src, mask)
			return true, false, c.storeX(ins.Args[2].Reg, "%"+call)
		}
		return false, false, nil

	case "VPSHUFD":
		// VPSHUFD $imm, Ysrc, Ydst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPSHUFD expects $imm, Ysrc, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		imm := uint64(ins.Args[0].Imm) & 0xff
		idx := func(k uint) uint64 { return (imm >> (2 * k)) & 3 }
		src, err := c.loadY(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <8 x i32>\n", bc, src)
		mask := fmt.Sprintf("<8 x i32> <i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d>",
			idx(0), idx(1), idx(2), idx(3),
			4+idx(0), 4+idx(1), 4+idx(2), 4+idx(3))
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i32> %%%s, <8 x i32> zeroinitializer, %s\n", sh, bc, mask)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i32> %%%s to <32 x i8>\n", out, sh)
		return true, false, c.storeY(ins.Args[2].Reg, "%"+out)

	case "VPSLLD", "VPSRLD":
		// VPS*D $imm, Ysrc, Ydst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, Ysrc, Ydst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm & 31
		src, err := c.loadY(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <8 x i32>\n", bc, src)
		sh := c.newTmp()
		if op == "VPSLLD" {
			fmt.Fprintf(c.b, "  %%%s = shl <8 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n, n, n, n, n)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr <8 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n, n, n, n, n)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i32> %%%s to <32 x i8>\n", out, sh)
		return true, false, c.storeY(ins.Args[2].Reg, "%"+out)

	case "VPSRLQ", "VPSLLQ":
		// VPSR/LQ $imm, Ysrc, Ydst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, Ysrc, Ydst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm & 63
		src, err := c.loadY(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", bc, src)
		sh := c.newTmp()
		if op == "VPSLLQ" {
			fmt.Fprintf(c.b, "  %%%s = shl <4 x i64> %%%s, <i64 %d, i64 %d, i64 %d, i64 %d>\n", sh, bc, n, n, n, n)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr <4 x i64> %%%s, <i64 %d, i64 %d, i64 %d, i64 %d>\n", sh, bc, n, n, n, n)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i64> %%%s to <32 x i8>\n", out, sh)
		return true, false, c.storeY(ins.Args[2].Reg, "%"+out)

	case "VPALIGNR":
		// VPALIGNR $imm, Ysrc1, Ysrc2, Ydst ; dst = alignr(src2, src1, imm)
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPALIGNR expects $imm, Ysrc1, Ysrc2, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[3].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm
		if n < 0 {
			n = 0
		}
		if n > 255 {
			n = 255
		}
		src1, err := c.loadY(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		src2, err := c.loadY(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		lo1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", lo1, src1, llvmI32RangeMask(0, 16))
		hi1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", hi1, src1, llvmI32RangeMask(16, 16))
		lo2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", lo2, src2, llvmI32RangeMask(0, 16))
		hi2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", hi2, src2, llvmI32RangeMask(16, 16))
		outLo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> %%%s, <16 x i32> %s\n", outLo, lo2, lo1, llvmAlignRightBytesMask(n))
		outHi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> %%%s, <16 x i32> %s\n", outHi, hi2, hi1, llvmAlignRightBytesMask(n))
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> %%%s, <32 x i32> %s\n", out, outLo, outHi, llvmI32RangeMask(0, 32))
		return true, false, c.storeY(ins.Args[3].Reg, "%"+out)

	case "VPERM2I128":
		// VPERM2I128 $imm, Ysrc1, Ysrc2, Ydst
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPERM2I128 expects $imm, Ysrc1, Ysrc2, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[3].Reg); !ok {
			return false, false, nil
		}
		imm := uint64(ins.Args[0].Imm) & 0xff
		// AT&T order: imm, src1, src2, dst ; choose lanes from src2 (arg2) + src1 (arg1).
		src1, err := c.loadYVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		src2, err := c.loadYVecOperand(ins.Args[2])
		if err != nil {
			return true, false, err
		}
		sel := func(bits uint64) int {
			switch bits & 0x3 {
			case 0:
				return 0 // src2 low
			case 1:
				return 1 // src2 high
			case 2:
				return 2 // src1 low
			default:
				return 3 // src1 high
			}
		}
		lowSel := sel(imm)
		hiSel := sel(imm >> 4)
		mask := fmt.Sprintf("<4 x i32> <i32 %d, i32 %d, i32 %d, i32 %d>", lowSel, lowSel+4, hiSel, hiSel+4)
		b2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", b2, src2)
		b1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", b1, src1)
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i64> %%%s, <4 x i64> %%%s, %s\n", sh, b2, b1, mask)
		// Zeroing controls.
		zeroLo := (imm>>3)&1 == 1
		zeroHi := (imm>>7)&1 == 1
		if zeroLo || zeroHi {
			cur := "%" + sh
			if zeroLo {
				i0 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %s, i64 0, i32 0\n", i0, cur)
				i1 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %%%s, i64 0, i32 1\n", i1, i0)
				cur = "%" + i1
			}
			if zeroHi {
				i2 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %s, i64 0, i32 2\n", i2, cur)
				i3 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %%%s, i64 0, i32 3\n", i3, i2)
				cur = "%" + i3
			}
			sh = strings.TrimPrefix(cur, "%")
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i64> %%%s to <32 x i8>\n", out, sh)
		return true, false, c.storeY(ins.Args[3].Reg, "%"+out)

	case "VINSERTI128":
		// VINSERTI128 $imm, Xsrc, Ysrc, Ydst
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VINSERTI128 expects $imm, Xsrc, Ysrc, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[3].Reg); !ok {
			return false, false, nil
		}
		imm := ins.Args[0].Imm & 1
		xsrc, err := c.loadXVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		ysrc, err := c.loadY(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		y64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", y64, ysrc)
		x64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", x64, xsrc)
		i0 := c.newTmp()
		i1 := c.newTmp()
		if imm == 0 {
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", i0, x64)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 1\n", i1, x64)
			s0 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %%%s, i64 %%%s, i32 0\n", s0, y64, i0)
			s1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %%%s, i64 %%%s, i32 1\n", s1, s0, i1)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i64> %%%s to <32 x i8>\n", out, s1)
			return true, false, c.storeY(ins.Args[3].Reg, "%"+out)
		}
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", i0, x64)
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 1\n", i1, x64)
		s0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %%%s, i64 %%%s, i32 2\n", s0, y64, i0)
		s1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i64> %%%s, i64 %%%s, i32 3\n", s1, s0, i1)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i64> %%%s to <32 x i8>\n", out, s1)
		return true, false, c.storeY(ins.Args[3].Reg, "%"+out)

	case "VMOVNTDQ":
		// VMOVNTDQ Ysrc, mem
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VMOVNTDQ expects Ysrc, dst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadY(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		switch ins.Args[1].Kind {
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store <32 x i8> %s, ptr %s, align 1\n", src, p)
			return true, false, nil
		case OpSym:
			p, err := c.ptrFromSB(ins.Args[1].Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store <32 x i8> %s, ptr %s, align 1\n", src, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 VMOVNTDQ unsupported dst: %q", ins.Raw)
		}

	case "AESENC", "AESENCLAST", "AESDEC", "AESDECLAST":
		// Two-operand form: OP Xsrc, Xdst
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		src2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", src2, src)
		dst2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", dst2, dstv)
		intr := map[Op]string{
			"AESENC":     "@llvm.x86.aesni.aesenc",
			"AESENCLAST": "@llvm.x86.aesni.aesenclast",
			"AESDEC":     "@llvm.x86.aesni.aesdec",
			"AESDECLAST": "@llvm.x86.aesni.aesdeclast",
		}[op]
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> %s(<2 x i64> %%%s, <2 x i64> %%%s)\n", call, intr, dst2, src2)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, call)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+bc)

	case "AESIMC":
		// Two-operand form: AESIMC Xsrc, Xdst
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 AESIMC expects Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		src2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", src2, src)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64> %%%s)\n", call, src2)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, call)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+bc)

	case "AESKEYGENASSIST":
		// Three-operand form: AESKEYGENASSIST $imm, Xsrc, Xdst
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 AESKEYGENASSIST expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		if ins.Args[0].Kind != OpImm {
			return true, false, fmt.Errorf("amd64 AESKEYGENASSIST expects immediate first operand: %q", ins.Raw)
		}
		imm := ins.Args[0].Imm & 0xff
		src, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		src2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", src2, src)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aeskeygenassist(<2 x i64> %%%s, i8 %d)\n", call, src2, imm)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, call)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+bc)

	case "VPTEST":
		// VPTEST Ysrc1, Ysrc2 (sets flags based on bitwise tests; used with JZ/JNZ).
		// We implement the ZF behavior (ZF=1 iff (a&b)==0) since stdlib uses JNZ.
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPTEST expects Ysrc1, Ysrc2: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadY(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadY(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		and := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and <32 x i8> %s, %s\n", and, a, b)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %%%s to <4 x i64>\n", bc, and)
		e0, e1, e2, e3 := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i64> %%%s, i32 0\n", e0, bc)
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i64> %%%s, i32 1\n", e1, bc)
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i64> %%%s, i32 2\n", e2, bc)
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i64> %%%s, i32 3\n", e3, bc)
		o01 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", o01, e0, e1)
		o23 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", o23, e2, e3)
		o := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", o, o01, o23)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, 0\n", z, o)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
		// CF/other flags are not used by stdlib here; clear CF to avoid stale reads.
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		return true, false, nil

	case "PCMPESTRI":
		// PCMPESTRI $imm, mem, Xsrc (implicit lengths; result index in ECX).
		//
		// LLVM 19 has backend issues selecting the native X86ISD::PCMPESTR node
		// for the corresponding intrinsic in some environments. For now we
		// emulate the subset used by the Go stdlib:
		//   imm=0x0c: unsigned byte compare, equal ordered, first match.
		//
		// We compute the first offset i in [0..15] where:
		// - bytes(mem[i:]) has a prefix that matches Xsrc[0:lenA]
		// - or a partial match at the end of the 16-byte block (to drive the
		//   stdlib's "partial match" control flow).
		// If no match/partial match exists, return 16.
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PCMPESTRI expects $imm, mem, Xsrc: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		imm := int64(ins.Args[0].Imm) & 0xff
		if imm != 0x0c {
			return true, false, fmt.Errorf("amd64 PCMPESTRI: unsupported imm 0x%x (only 0x0c supported): %q", imm, ins.Raw)
		}

		// A: needle bytes.
		a, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		// B: 16-byte haystack chunk.
		var bvec string
		switch ins.Args[1].Kind {
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
			bvec = "%" + ld
		case OpSym:
			p, err := c.ptrFromSB(ins.Args[1].Sym)
			if err != nil {
				return true, false, err
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
			bvec = "%" + ld
		default:
			return true, false, fmt.Errorf("amd64 PCMPESTRI unsupported mem operand: %q", ins.Raw)
		}

		ax, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		la := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", la, ax)

		allOnes := llvmAllOnesI8Vec(16)
		idx := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i32 0, 16\n", idx)
		prev := "%" + idx

		// Build first-match index using a select chain.
		for i := 0; i < 16; i++ {
			// Shuffle B so that element 0 is B[i], padding beyond 16 with 0.
			maskElts := make([]string, 0, 16)
			for k := 0; k < 16; k++ {
				j := i + k
				if j < 16 {
					maskElts = append(maskElts, fmt.Sprintf("i32 %d", j))
				} else {
					// 16 selects element 0 of the second (zero) vector.
					maskElts = append(maskElts, "i32 16")
				}
			}
			mask := "<16 x i32> <" + strings.Join(maskElts, ", ") + ">"

			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> zeroinitializer, %s\n", sh, bvec, mask)
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq <16 x i8> %%%s, %s\n", cmp, sh, a)
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select <16 x i1> %%%s, <16 x i8> %s, <16 x i8> zeroinitializer\n", sel, cmp, allOnes)
			pm := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %%%s)\n", pm, sel)

			// minLen = min(lenA, 16-i)
			cap := 16 - i
			lt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %%%s, %d\n", lt, la, cap)
			min := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %d\n", min, lt, la, cap)
			sh1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i32 1, %%%s\n", sh1, min)
			req := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", req, sh1)
			have := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %%%s\n", have, pm, req)
			okt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, %%%s\n", okt, have, req)

			unset := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 16\n", unset, prev)
			take := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", take, okt, unset)
			next := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %d, i32 %s\n", next, take, i, prev)
			prev = "%" + next
		}

		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, prev)
		return true, false, c.storeReg(CX, "%"+z)

	case "VPAND":
		// VPAND Ysrc1, Ysrc2, Ydst
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPAND expects Ysrc1, Ysrc2, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadYVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		b, err := c.loadYVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and <32 x i8> %s, %s\n", t, a, b)
		return true, false, c.storeY(ins.Args[2].Reg, "%"+t)

	case "VPBLENDD":
		// VPBLENDD $imm, Ysrc1, Ysrc2, Ydst
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPBLENDD expects $imm, Ysrc1, Ysrc2, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[3].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadYVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		b, err := c.loadYVecOperand(ins.Args[2])
		if err != nil {
			return true, false, err
		}
		imm := uint64(ins.Args[0].Imm) & 0xff
		av := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <8 x i32>\n", av, a)
		bv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <8 x i32>\n", bv, b)
		mask := make([]string, 0, 8)
		for i := 0; i < 8; i++ {
			if ((imm >> i) & 1) != 0 {
				mask = append(mask, fmt.Sprintf("i32 %d", i))
			} else {
				mask = append(mask, fmt.Sprintf("i32 %d", 8+i))
			}
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i32> %%%s, <8 x i32> %%%s, <8 x i32> <%s>\n", sh, av, bv, strings.Join(mask, ", "))
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i32> %%%s to <32 x i8>\n", out, sh)
		return true, false, c.storeY(ins.Args[3].Reg, "%"+out)

	case "VPBROADCASTB":
		// VPBROADCASTB Xsrc, Ydst (broadcast low byte to all 32 bytes).
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPBROADCASTB expects Xsrc, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		xv, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		e := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 0\n", e, xv)
		ins0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <32 x i8> undef, i8 %%%s, i32 0\n", ins0, e)
		spl := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %%%s, <32 x i8> zeroinitializer, <32 x i32> zeroinitializer\n", spl, ins0)
		return true, false, c.storeY(ins.Args[1].Reg, "%"+spl)

	case "VPSRLDQ", "VPSLLDQ":
		// VPSR/LLDQ $imm, Ysrc, Ydst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, Ysrc, Ydst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm
		if n < 0 {
			n = 0
		}
		if n > 16 {
			n = 16
		}
		src, err := c.loadY(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", lo, src, llvmI32RangeMask(0, 16))
		hi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", hi, src, llvmI32RangeMask(16, 16))
		lo2 := c.newTmp()
		hi2 := c.newTmp()
		if op == "VPSLLDQ" {
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> zeroinitializer, <16 x i32> %s\n", lo2, lo, llvmShiftLeftBytesMask(n))
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> zeroinitializer, <16 x i32> %s\n", hi2, hi, llvmShiftLeftBytesMask(n))
		} else {
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> zeroinitializer, <16 x i32> %s\n", lo2, lo, llvmShiftRightBytesMask(n))
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> zeroinitializer, <16 x i32> %s\n", hi2, hi, llvmShiftRightBytesMask(n))
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %%%s, <16 x i8> %%%s, <32 x i32> %s\n", out, lo2, hi2, llvmI32RangeMask(0, 32))
		return true, false, c.storeY(ins.Args[2].Reg, "%"+out)

	case "PUNPCKLBW":
		// PUNPCKLBW Xsrc, Xdst
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PUNPCKLBW expects Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		// Interleave low 8 bytes: dst = [dst0,src0,dst1,src1,...,dst7,src7].
		src, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		mask := "<16 x i32> <i32 0, i32 16, i32 1, i32 17, i32 2, i32 18, i32 3, i32 19, i32 4, i32 20, i32 5, i32 21, i32 6, i32 22, i32 7, i32 23>"
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, %s\n", sh, dstv, src, mask)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+sh)

	case "PSHUFL", "PSHUFD":
		// PSHUFL $imm, Xsrc, Xdst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, Xsrc, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		imm := uint64(ins.Args[0].Imm) & 0xff
		idx := func(k uint) uint64 { return (imm >> (2 * k)) & 3 }
		src, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc1, src)
		mask := fmt.Sprintf("<4 x i32> <i32 %d, i32 %d, i32 %d, i32 %d>", idx(0), idx(1), idx(2), idx(3))
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i32> %%%s, <4 x i32> zeroinitializer, %s\n", sh, bc1, mask)
		bc2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc2, sh)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+bc2)

	case "PSHUFHW":
		// PSHUFHW $imm, Xsrc, Xdst (shuffle high 4 words; low 4 words unchanged).
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PSHUFHW expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		imm := uint64(ins.Args[0].Imm) & 0xff
		idx := func(k uint) uint64 { return (imm >> (2 * k)) & 3 }
		src, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", bc1, src)
		mask := fmt.Sprintf("<8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 %d, i32 %d, i32 %d, i32 %d>",
			4+idx(0), 4+idx(1), 4+idx(2), 4+idx(3))
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i16> %%%s, <8 x i16> zeroinitializer, %s\n", sh, bc1, mask)
		bc2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %%%s to <16 x i8>\n", bc2, sh)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+bc2)

	case "SHUFPS":
		// SHUFPS $imm, Xsrc, Xdst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 SHUFPS expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		imm := uint64(ins.Args[0].Imm) & 0xff
		idx := func(k uint) uint64 { return (imm >> (2 * k)) & 3 }
		src, err := c.loadXVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		ds := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", ds, dstv)
		ss := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", ss, src)
		mask := fmt.Sprintf("<4 x i32> <i32 %d, i32 %d, i32 %d, i32 %d>", idx(0), idx(1), 4+idx(2), 4+idx(3))
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i32> %%%s, <4 x i32> %%%s, %s\n", sh, ds, ss, mask)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bc, sh)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+bc)

	case "PBLENDW":
		// PBLENDW $imm, Xsrc, Xdst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PBLENDW expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		imm := uint64(ins.Args[0].Imm) & 0xff
		sv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", sv, src)
		dv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", dv, dstv)
		mask := make([]string, 0, 8)
		for i := 0; i < 8; i++ {
			if ((imm >> i) & 1) != 0 {
				mask = append(mask, fmt.Sprintf("i32 %d", 8+i))
			} else {
				mask = append(mask, fmt.Sprintf("i32 %d", i))
			}
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i16> %%%s, <8 x i16> %%%s, <8 x i32> <%s>\n", sh, dv, sv, strings.Join(mask, ", "))
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %%%s to <16 x i8>\n", out, sh)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+out)

	case "SHA256MSG1", "SHA256MSG2":
		// Approximate scheduling helpers as per-lane adds to keep SSA flow.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		s32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", s32, src)
		d32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", d32, dstv)
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, %%%s\n", add, d32, s32)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, add)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "SHA1NEXTE", "SHA1MSG1", "SHA1MSG2":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		s32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", s32, src)
		d32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", d32, dstv)
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, %%%s\n", add, d32, s32)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, add)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "SHA1RNDS4":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 SHA1RNDS4 expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		s32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", s32, src)
		d32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", d32, dstv)
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, %%%s\n", add, d32, s32)
		immv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d>\n", immv, add, ins.Args[0].Imm, ins.Args[0].Imm, ins.Args[0].Imm, ins.Args[0].Imm)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, immv)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+out)

	case "SHA256RNDS2":
		// SHA256RNDS2 Xsrc, Xstate, Xdst
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 SHA256RNDS2 expects Xsrc, Xstate, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		b, err := c.loadXVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		a32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", a32, a)
		b32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", b32, b)
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add <4 x i32> %%%s, %%%s\n", add, a32, b32)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, add)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+out)

	case "VMOVDQU64":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 VMOVDQU64 expects src, dst: %q", ins.Raw)
		}
		if ins.Args[1].Kind == OpReg {
			if _, ok := amd64ParseZReg(ins.Args[1].Reg); ok {
				if ins.Args[0].Kind == OpReg {
					if _, ok := amd64ParseZReg(ins.Args[0].Reg); !ok {
						return false, false, nil
					}
					v, err := c.loadZ(ins.Args[0].Reg)
					if err != nil {
						return true, false, err
					}
					return true, false, c.storeZ(ins.Args[1].Reg, v)
				}
				switch ins.Args[0].Kind {
				case OpMem:
					addr, err := c.addrFromMem(ins.Args[0].Mem)
					if err != nil {
						return true, false, err
					}
					p := c.ptrFromAddrI64(addr)
					ld := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = load <64 x i8>, ptr %s, align 1\n", ld, p)
					return true, false, c.storeZ(ins.Args[1].Reg, "%"+ld)
				case OpSym:
					p, err := c.ptrFromSB(ins.Args[0].Sym)
					if err != nil {
						return true, false, err
					}
					ld := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = load <64 x i8>, ptr %s, align 1\n", ld, p)
					return true, false, c.storeZ(ins.Args[1].Reg, "%"+ld)
				default:
					return true, false, fmt.Errorf("amd64 VMOVDQU64 unsupported src: %q", ins.Raw)
				}
			}
		}
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseZReg(ins.Args[0].Reg); ok {
				src, err := c.loadZ(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				switch ins.Args[1].Kind {
				case OpMem:
					addr, err := c.addrFromMem(ins.Args[1].Mem)
					if err != nil {
						return true, false, err
					}
					p := c.ptrFromAddrI64(addr)
					fmt.Fprintf(c.b, "  store <64 x i8> %s, ptr %s, align 1\n", src, p)
					return true, false, nil
				case OpSym:
					p, err := c.ptrFromSB(ins.Args[1].Sym)
					if err != nil {
						return true, false, err
					}
					fmt.Fprintf(c.b, "  store <64 x i8> %s, ptr %s, align 1\n", src, p)
					return true, false, nil
				case OpReg:
					if _, ok := amd64ParseZReg(ins.Args[1].Reg); ok {
						return true, false, c.storeZ(ins.Args[1].Reg, src)
					}
				}
			}
		}
		return false, false, nil

	case "VMOVDQU":
		// VMOVDQU load/store for X/Y regs.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 VMOVDQU expects src, dst: %q", ins.Raw)
		}
		if ins.Args[1].Kind == OpReg {
			if _, ok := amd64ParseYReg(ins.Args[1].Reg); ok {
				if ins.Args[0].Kind == OpReg {
					if _, ok := amd64ParseYReg(ins.Args[0].Reg); !ok {
						return false, false, nil
					}
					v, err := c.loadY(ins.Args[0].Reg)
					if err != nil {
						return true, false, err
					}
					return true, false, c.storeY(ins.Args[1].Reg, v)
				}
				var p string
				switch ins.Args[0].Kind {
				case OpMem:
					addr, err := c.addrFromMem(ins.Args[0].Mem)
					if err != nil {
						return true, false, err
					}
					p = c.ptrFromAddrI64(addr)
				case OpSym:
					ps, err := c.ptrFromSB(ins.Args[0].Sym)
					if err != nil {
						return true, false, err
					}
					p = ps
				default:
					return true, false, fmt.Errorf("amd64 VMOVDQU unsupported src: %q", ins.Raw)
				}
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load <32 x i8>, ptr %s, align 1\n", ld, p)
				return true, false, c.storeY(ins.Args[1].Reg, "%"+ld)
			}
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); ok {
				if ins.Args[0].Kind == OpReg {
					if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
						return false, false, nil
					}
					v, err := c.loadX(ins.Args[0].Reg)
					if err != nil {
						return true, false, err
					}
					return true, false, c.storeX(ins.Args[1].Reg, v)
				}
				switch ins.Args[0].Kind {
				case OpMem:
					addr, err := c.addrFromMem(ins.Args[0].Mem)
					if err != nil {
						return true, false, err
					}
					p := c.ptrFromAddrI64(addr)
					ld := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
					return true, false, c.storeX(ins.Args[1].Reg, "%"+ld)
				case OpSym:
					p, err := c.ptrFromSB(ins.Args[0].Sym)
					if err != nil {
						return true, false, err
					}
					ld := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
					return true, false, c.storeX(ins.Args[1].Reg, "%"+ld)
				default:
					return true, false, fmt.Errorf("amd64 VMOVDQU unsupported src: %q", ins.Raw)
				}
			}
			return false, false, nil
		}
		if ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VMOVDQU expects Ysrc for store form: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[0].Reg); ok {
			src, err := c.loadY(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			switch ins.Args[1].Kind {
			case OpMem:
				addr, err := c.addrFromMem(ins.Args[1].Mem)
				if err != nil {
					return true, false, err
				}
				p := c.ptrFromAddrI64(addr)
				fmt.Fprintf(c.b, "  store <32 x i8> %s, ptr %s, align 1\n", src, p)
				return true, false, nil
			case OpSym:
				p, err := c.ptrFromSB(ins.Args[1].Sym)
				if err != nil {
					return true, false, err
				}
				fmt.Fprintf(c.b, "  store <32 x i8> %s, ptr %s, align 1\n", src, p)
				return true, false, nil
			default:
				return true, false, fmt.Errorf("amd64 VMOVDQU unsupported dst: %q", ins.Raw)
			}
		}
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); ok {
			src, err := c.loadX(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			switch ins.Args[1].Kind {
			case OpMem:
				addr, err := c.addrFromMem(ins.Args[1].Mem)
				if err != nil {
					return true, false, err
				}
				p := c.ptrFromAddrI64(addr)
				fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", src, p)
				return true, false, nil
			case OpSym:
				p, err := c.ptrFromSB(ins.Args[1].Sym)
				if err != nil {
					return true, false, err
				}
				fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", src, p)
				return true, false, nil
			default:
				return true, false, fmt.Errorf("amd64 VMOVDQU unsupported dst: %q", ins.Raw)
			}
		}
		return false, false, nil

	case "VPCMPEQB":
		// VPCMPEQB Ysrc1, Ysrc2, Ydst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPCMPEQB expects Ysrc1, Ysrc2, Ydst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		a, err := c.loadY(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadY(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		allOnes := llvmAllOnesI8Vec(32)
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq <32 x i8> %s, %s\n", cmp, a, b)
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <32 x i1> %%%s, <32 x i8> %s, <32 x i8> zeroinitializer\n", sel, cmp, allOnes)
		return true, false, c.storeY(ins.Args[2].Reg, "%"+sel)

	case "VPMOVMSKB":
		// VPMOVMSKB Ysrc, dstReg
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPMOVMSKB expects Ysrc, dstReg: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		v, err := c.loadY(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		// Work around LLVM backend issues with the AVX2 pmovmskb intrinsic by
		// splitting the 256-bit vector into two 128-bit halves and using the SSE2
		// pmovmskb.128 intrinsic.
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", lo, v, llvmI32RangeMask(0, 16))
		hi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> zeroinitializer, <16 x i32> %s\n", hi, v, llvmI32RangeMask(16, 16))
		ml := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %%%s)\n", ml, lo)
		mh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %%%s)\n", mh, hi)
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, 16\n", sh, mh)
		or := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", or, sh, ml)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, or)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)

	case "MOVOU", "MOVOA":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		if ins.Args[1].Kind == OpReg {
			if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
				return false, false, nil
			}
			dst := ins.Args[1].Reg
			switch ins.Args[0].Kind {
			case OpReg:
				v, err := c.loadX(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				return true, false, c.storeX(dst, v)
			case OpMem:
				addr, err := c.addrFromMem(ins.Args[0].Mem)
				if err != nil {
					return true, false, err
				}
				p := c.ptrFromAddrI64(addr)
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
				return true, false, c.storeX(dst, "%"+ld)
			case OpSym:
				p, err := c.ptrFromSB(ins.Args[0].Sym)
				if err != nil {
					return true, false, err
				}
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
				return true, false, c.storeX(dst, "%"+ld)
			default:
				return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
			}
		}

		if ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc for store form: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		srcv, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		switch ins.Args[1].Kind {
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", srcv, p)
			return true, false, nil
		case OpSym:
			p, err := c.ptrFromSB(ins.Args[1].Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", srcv, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported dst: %q", op, ins.Raw)
		}

	case "PXOR", "PAND", "PANDN":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		if op == "PXOR" {
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", t, dstv, src)
		} else if op == "PANDN" {
			notv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <16 x i8> %s, %s\n", notv, dstv, llvmAllOnesI8Vec(16))
			fmt.Fprintf(c.b, "  %%%s = and <16 x i8> %%%s, %s\n", t, notv, src)
		} else {
			fmt.Fprintf(c.b, "  %%%s = and <16 x i8> %s, %s\n", t, dstv, src)
		}
		return true, false, c.storeX(ins.Args[1].Reg, "%"+t)

	case "PADDL", "PADDD", "PADDQ", "PSUBL":
		// Two-operand packed arithmetic: dst = dst (+|-) src.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		vecTy := "<4 x i32>"
		if op == "PADDQ" {
			vecTy = "<2 x i64>"
		}
		as := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", as, src, vecTy)
		bs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bs, dstv, vecTy)
		x := c.newTmp()
		if op == "PADDL" || op == "PADDD" || op == "PADDQ" {
			fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", x, vecTy, bs, as)
		} else {
			fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", x, vecTy, bs, as)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecTy, x)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "PSLLL", "PSRLL", "PSRAL":
		// Two-operand packed i32 shift immediate.
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm & 31
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc, v)
		sh := c.newTmp()
		switch op {
		case "PSLLL":
			fmt.Fprintf(c.b, "  %%%s = shl <4 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n)
		case "PSRLL":
			fmt.Fprintf(c.b, "  %%%s = lshr <4 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n)
		case "PSRAL":
			fmt.Fprintf(c.b, "  %%%s = ashr <4 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, sh)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "PCMPEQL":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PCMPEQL expects Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		as := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", as, src)
		bs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bs, dstv)
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq <4 x i32> %%%s, %%%s\n", cmp, bs, as)
		sext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext <4 x i1> %%%s to <4 x i32>\n", sext, cmp)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, sext)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "VPCLMULQDQ":
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPCLMULQDQ expects $imm, Zsrc, Zdst, Zout: %q", ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseZReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseZReg(ins.Args[3].Reg); !ok {
			return false, false, nil
		}
		imm := ins.Args[0].Imm & 0xff
		src, err := c.loadZ(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadZ(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		bd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <64 x i8> %s to <8 x i64>\n", bd, dstv)
		bs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <64 x i8> %s to <8 x i64>\n", bs, src)
		lanes := make([]string, 0, 4)
		for i := 0; i < 4; i++ {
			dlane := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i64> %%%s, <8 x i64> zeroinitializer, <2 x i32> <i32 %d, i32 %d>\n", dlane, bd, i*2, i*2+1)
			slane := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i64> %%%s, <8 x i64> zeroinitializer, <2 x i32> <i32 %d, i32 %d>\n", slane, bs, i*2, i*2+1)
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %%%s, <2 x i64> %%%s, i8 %d)\n", call, dlane, slane, imm)
			lanes = append(lanes, "%"+call)
		}
		merged0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", merged0, lanes[0], lanes[1])
		merged1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", merged1, lanes[2], lanes[3])
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i64> %%%s, <4 x i64> %%%s, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>\n", merged, merged0, merged1)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i64> %%%s to <64 x i8>\n", out, merged)
		return true, false, c.storeZ(ins.Args[3].Reg, "%"+out)

	case "VPTERNLOGD":
		if len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[3].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPTERNLOGD expects $imm, src1, src2, dst: %q", ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[3].Reg); ok {
			if ins.Args[1].Kind == OpReg {
				if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
					return false, false, nil
				}
			}
			if ins.Args[2].Kind == OpReg {
				if _, ok := amd64ParseYReg(ins.Args[2].Reg); !ok {
					return false, false, nil
				}
			}
			if ins.Args[0].Imm != 0x96 {
				return true, false, fmt.Errorf("amd64 VPTERNLOGD only supports imm 0x96 for now: %q", ins.Raw)
			}
			a, err := c.loadYVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadYVecOperand(ins.Args[2])
			if err != nil {
				return true, false, err
			}
			dstv, err := c.loadY(ins.Args[3].Reg)
			if err != nil {
				return true, false, err
			}
			x1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <32 x i8> %s, %s\n", x1, dstv, a)
			x2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <32 x i8> %%%s, %s\n", x2, x1, b)
			return true, false, c.storeY(ins.Args[3].Reg, "%"+x2)
		}
		if _, ok := amd64ParseZReg(ins.Args[3].Reg); !ok {
			return false, false, nil
		}
		if ins.Args[0].Imm != 0x96 {
			return true, false, fmt.Errorf("amd64 VPTERNLOGD only supports imm 0x96 for now: %q", ins.Raw)
		}
		a, err := c.loadZVecOperand(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		b, err := c.loadZVecOperand(ins.Args[2])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadZ(ins.Args[3].Reg)
		if err != nil {
			return true, false, err
		}
		x1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <64 x i8> %s, %s\n", x1, dstv, a)
		x2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <64 x i8> %%%s, %s\n", x2, x1, b)
		return true, false, c.storeZ(ins.Args[3].Reg, "%"+x2)

	case "VEXTRACTF32X4":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VEXTRACTF32X4 expects $imm, Zsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseZReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		idx := int(ins.Args[0].Imm & 0x3)
		src, err := c.loadZ(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <64 x i8> %s, <64 x i8> zeroinitializer, <16 x i32> %s\n", out, src, llvmI32RangeMask(idx*16, 16))
		return true, false, c.storeX(ins.Args[2].Reg, "%"+out)

	case "PCLMULQDQ":
		// PCLMULQDQ $imm, Xsrc, Xdst  => Xdst = pclmul(Xdst, Xsrc, imm)
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PCLMULQDQ expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		imm := ins.Args[0].Imm & 0xff
		src, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		bd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bd, dstv)
		bs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bs, src)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> %%%s, <2 x i64> %%%s, i8 %d)\n", call, bd, bs, imm)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, call)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+bc)

	case "PCMPEQB":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PCMPEQB expects Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		allOnes := llvmAllOnesI8Vec(16)
		// Common idiom: PCMPEQB X3, X3 -> all ones.
		if ins.Args[0].Reg == ins.Args[1].Reg {
			return true, false, c.storeX(ins.Args[1].Reg, allOnes)
		}
		srcv, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq <16 x i8> %s, %s\n", cmp, dstv, srcv)
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <16 x i1> %%%s, <16 x i8> %s, <16 x i8> zeroinitializer\n", sel, cmp, allOnes)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+sel)

	case "PMOVMSKB":
		// PMOVMSKB Xsrc, dstReg
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PMOVMSKB expects Xsrc, dstReg: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
			return false, false, nil
		}
		v, err := c.loadX(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8> %s)\n", call, v)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, call)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)

	case "PSHUFB":
		// PSHUFB Xmask, Xdst
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PSHUFB expects Xmask, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		mask, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8> %s, <16 x i8> %s)\n", call, dst, mask)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+call)

	case "PINSRQ":
		// PINSRQ $imm, src64, Xdst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PINSRQ expects $imm, src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		idx := ins.Args[0].Imm & 1
		src, err := c.evalI64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, dst)
		insv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %s, i32 %d\n", insv, bc, src, idx)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, insv)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+out)

	case "PINSRD":
		// PINSRD $imm, src32, Xdst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PINSRD expects $imm, src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		idx := ins.Args[0].Imm & 3
		src64, err := c.evalI64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		src32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", src32, src64)
		dst, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc, dst)
		insv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %%%s, i32 %%%s, i32 %d\n", insv, bc, src32, idx)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, insv)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+out)

	case "PINSRW":
		// PINSRW $imm, src16, Xdst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PINSRW expects $imm, src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		idx := ins.Args[0].Imm & 7
		src64, err := c.evalI64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		src16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", src16, src64)
		dst, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <8 x i16>\n", bc, dst)
		insv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <8 x i16> %%%s, i16 %%%s, i32 %d\n", insv, bc, src16, idx)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %%%s to <16 x i8>\n", out, insv)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+out)

	case "PINSRB":
		// PINSRB $imm, src8, Xdst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PINSRB expects $imm, src, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		idx := ins.Args[0].Imm & 15
		src64, err := c.evalI64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		src8 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", src8, src64)
		dst, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		insv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i8> %s, i8 %%%s, i32 %d\n", insv, dst, src8, idx)
		return true, false, c.storeX(ins.Args[2].Reg, "%"+insv)

	case "PEXTRB":
		// PEXTRB $imm, Xsrc, dst
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PEXTRB expects $imm, Xsrc, dst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		idx := ins.Args[0].Imm & 15
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		ex := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", ex, v, idx)
		switch ins.Args[2].Kind {
		case OpReg:
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", z, ex)
			return true, false, c.storeReg(ins.Args[2].Reg, "%"+z)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[2].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s, align 1\n", ex, p)
			return true, false, nil
		case OpSym:
			p, err := c.ptrFromSB(ins.Args[2].Sym)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s, align 1\n", ex, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 PEXTRB unsupported dst: %q", ins.Raw)
		}

	case "PEXTRQ":
		// PEXTRQ $imm, Xsrc, dstReg|dstMem (extract 64-bit lane)
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PEXTRQ expects $imm, Xsrc, dstReg|dstMem: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		imm := ins.Args[0].Imm & 1
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, v)
		ex := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 %d\n", ex, bc, imm)
		switch ins.Args[2].Kind {
		case OpReg:
			return true, false, c.storeReg(ins.Args[2].Reg, "%"+ex)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[2].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s, align 1\n", ex, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 PEXTRQ expects reg or mem destination: %q", ins.Raw)
		}

	case "PALIGNR":
		// PALIGNR $imm, Xsrc, Xdst ; dst = alignr(dst, src, imm)
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PALIGNR expects $imm, Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm
		if n < 0 {
			n = 0
		}
		if n > 255 {
			n = 255
		}
		src, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		dst, err := c.loadX(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <16 x i32> %s\n", sh, dst, src, llvmAlignRightBytesMask(n))
		return true, false, c.storeX(ins.Args[2].Reg, "%"+sh)

	case "PSRLDQ":
		// PSRLDQ $imm, Xdst
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PSRLDQ expects $imm, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm
		if n < 0 || n > 16 {
			return true, false, fmt.Errorf("amd64 PSRLDQ invalid imm %d: %q", n, ins.Raw)
		}
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		shuf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> zeroinitializer, <16 x i32> %s\n", shuf, v, llvmShiftRightBytesMask(n))
		return true, false, c.storeX(ins.Args[1].Reg, "%"+shuf)

	case "PSLLDQ":
		// PSLLDQ $imm, Xdst
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PSLLDQ expects $imm, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm
		if n < 0 || n > 16 {
			return true, false, fmt.Errorf("amd64 PSLLDQ invalid imm %d: %q", n, ins.Raw)
		}
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		shuf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> zeroinitializer, <16 x i32> %s\n", shuf, v, llvmShiftLeftBytesMask(n))
		return true, false, c.storeX(ins.Args[1].Reg, "%"+shuf)

	case "PSRLQ":
		// PSRLQ $imm, Xdst (shift each 64-bit lane right)
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PSRLQ expects $imm, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm & 63
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, v)
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr <2 x i64> %%%s, <i64 %d, i64 %d>\n", sh, bc, n, n)
		back := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", back, sh)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+back)

	case "PEXTRD":
		// PEXTRD $imm, Xsrc, dstReg|dstMem (extract 32-bit lane)
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PEXTRD expects $imm, Xsrc, dstReg|dstMem: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		imm := ins.Args[0].Imm & 3
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc, v)
		ex := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %%%s, i32 %d\n", ex, bc, imm)
		switch ins.Args[2].Kind {
		case OpReg:
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, ex)
			return true, false, c.storeReg(ins.Args[2].Reg, "%"+z)
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[2].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fmt.Fprintf(c.b, "  store i32 %%%s, ptr %s, align 1\n", ex, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 PEXTRD expects reg or mem destination: %q", ins.Raw)
		}
	}

	// Other MOVQ/MOVL cases are handled elsewhere.
	return false, false, nil
}

func llvmShiftRightBytesMask(n int64) string {
	// shufflevector mask for right shift by n bytes.
	// Use second vector's element 0 (index 16) as the "zero" source.
	var sb strings.Builder
	sb.WriteString("<")
	for i := 0; i < 16; i++ {
		if i != 0 {
			sb.WriteString(", ")
		}
		idx := int64(i) + n
		if idx < 16 {
			fmt.Fprintf(&sb, "i32 %d", idx)
		} else {
			sb.WriteString("i32 16")
		}
	}
	sb.WriteString(">")
	return sb.String()
}

func llvmShiftLeftBytesMask(n int64) string {
	// shufflevector mask for left shift by n bytes.
	// Use second vector's element 0 (index 16) as the "zero" source.
	var sb strings.Builder
	sb.WriteString("<")
	for i := 0; i < 16; i++ {
		if i != 0 {
			sb.WriteString(", ")
		}
		idx := int64(i) - n
		if idx >= 0 {
			fmt.Fprintf(&sb, "i32 %d", idx)
		} else {
			sb.WriteString("i32 16")
		}
	}
	sb.WriteString(">")
	return sb.String()
}

func llvmAlignRightBytesMask(n int64) string {
	// shufflevector mask for alignr(dst, src, n):
	// result bytes are selected from concatenation [dst, src], right shifted by n.
	var sb strings.Builder
	sb.WriteString("<")
	for i := 0; i < 16; i++ {
		if i != 0 {
			sb.WriteString(", ")
		}
		idx := int64(i) + n
		switch {
		case idx < 16:
			fmt.Fprintf(&sb, "i32 %d", idx)
		case idx < 32:
			fmt.Fprintf(&sb, "i32 %d", idx)
		default:
			sb.WriteString("i32 16")
		}
	}
	sb.WriteString(">")
	return sb.String()
}

func llvmRepeatI8Mask(chunk, width int) string {
	if chunk <= 0 {
		chunk = 1
	}
	var sb strings.Builder
	sb.WriteByte('<')
	for i := 0; i < width; i++ {
		if i != 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "i32 %d", i%chunk)
	}
	sb.WriteByte('>')
	return sb.String()
}

func llvmAllOnesI8Vec(n int) string {
	if n <= 0 {
		return "<>"
	}
	var b strings.Builder
	b.WriteString("<")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("i8 -1")
	}
	b.WriteString(">")
	return b.String()
}

func isAMD64ZReg(r Reg) bool {
	_, ok := amd64ParseZReg(r)
	return ok
}

func llvmI32RangeMask(start int, n int) string {
	// Build <n x i32> <start, start+1, ...>.
	if n <= 0 {
		return "<>"
	}
	var b strings.Builder
	b.WriteString("<")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "i32 %d", start+i)
	}
	b.WriteString(">")
	return b.String()
}

func amd64SelectZByAnyMask(c *amd64Ctx, src, mask string) string {
	nz := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %s, 0\n", nz, mask)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, <64 x i8> %s, <64 x i8> zeroinitializer\n", out, nz, src)
	return "%" + out
}

func amd64MaskBitI1(c *amd64Ctx, mask string, idx int) string {
	shifted := mask
	if idx > 0 {
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", sh, mask, idx)
		shifted = "%" + sh
	}
	one := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %s, 1\n", one, shifted)
	bit := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", bit, one)
	return "%" + bit
}

func amd64PackI1x8ToI64(c *amd64Ctx, pred string) string {
	acc := "0"
	for i := 0; i < 8; i++ {
		bit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i1> %s, i32 %d\n", bit, pred, i)
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", ext, bit)
		val := "%" + ext
		if i > 0 {
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", sh, ext, i)
			val = "%" + sh
		}
		orv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %s, %s\n", orv, acc, val)
		acc = "%" + orv
	}
	return acc
}

func amd64BytePopcountZ(c *amd64Ctx, src string) string {
	out := "zeroinitializer"
	for i := 0; i < 64; i++ {
		elt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <64 x i8> %s, i32 %d\n", elt, src, i)
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", ext, elt)
		pop := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctpop.i64(i64 %%%s)\n", pop, ext)
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", tr, pop)
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <64 x i8> %s, i8 %%%s, i32 %d\n", next, out, tr, i)
		out = "%" + next
	}
	return out
}
