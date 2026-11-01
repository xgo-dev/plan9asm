package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func (c *amd64Ctx) lowerVec(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if known, term, err := c.lowerSHA(op, ins); known {
		return known, term, err
	}
	if known, term, err := c.lowerSqrt(op, ins); known {
		return known, term, err
	}
	if known, term, err := c.lowerLegacyPackedMove(op, ins); known {
		return known, term, err
	}
	if ok, term, err := c.lowerFloatArithmetic(op, ins, ""); ok {
		return ok, term, err
	}
	if ok, terminated, err := c.lowerVectorZero(op, ins); ok {
		return ok, terminated, err
	}
	if ok, term, err := c.lowerInsertExtractFamily(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedLogicalFamily(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerFourSource(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedStringCompare(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerExplicitMaskMove(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPermute128(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerIndexedPermute(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerQwordBitLookup(op, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerMaskVectorMove(op, ins); ok {
		return ok, term, err
	}
	rawOp := op
	if ok, term, err := c.lowerSingleSourceIntegerNarrow(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedIntegerInsert(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerScalarFloatBroadcast(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerAES(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedWordShuffle(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedByteShuffle(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedBitCount(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedConflict(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedExpand(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerGFNI(rawOp, ins); ok {
		return ok, term, err
	}
	if ok, term, err := c.lowerPackedCompress(rawOp, ins); ok {
		return ok, term, err
	}
	zeroMasking := false
	if raw := string(op); strings.Contains(raw, ".") {
		for _, suffix := range strings.Split(raw, ".")[1:] {
			if suffix == "Z" {
				zeroMasking = true
			}
		}
		if i := strings.IndexByte(raw, '.'); i >= 0 {
			op = Op(raw[:i])
		}
	}
	if _, alias := x86GoMOVQSourceAliases[op]; alias {
		if rawOp != op {
			return true, false, fmt.Errorf("%s MOVD does not accept instruction suffixes: %q", c.goarch, ins.Raw)
		}
		if known, terminated, err := c.lowerMachineRegisterMove("MOVQ", ins); known {
			return known, terminated, err
		}
		if err := c.validateMOVDAliasForm(ins); err != nil {
			return true, false, err
		}
		// Go source aliases share AMOVQ's rows, not Intel's mnemonic scope.
		// Change local dispatch only; keep source/caller certificate identity.
		dispatch := ins
		dispatch.Op = op
		op = x86SourceMoveInstruction(dispatch, c.goarch).Op
	}
	if _, ok := amd64MaskMoveSpecs[op]; ok {
		if rawOp != op {
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", op, ins.Raw)
		}
		return true, false, c.lowerMaskMove(op, ins)
	}
	if _, ok := amd64GatherSpecs[op]; ok {
		if rawOp != op {
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", op, ins.Raw)
		}
		return true, false, c.lowerGather(op, ins)
	}
	if _, ok := amd64VSIBPrefetchSpecs[op]; ok {
		if rawOp != op {
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", op, ins.Raw)
		}
		return true, false, c.lowerGather(op, ins)
	}
	if _, ok := amd64MaskLogicalSpecs[op]; ok {
		if rawOp != op {
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", op, ins.Raw)
		}
		return true, false, c.lowerMaskLogical(op, ins)
	}
	if _, ok := amd64MaskArithmeticSpecs[op]; ok {
		if rawOp != op {
			return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, op, ins.Raw)
		}
		return true, false, c.lowerMaskArithmetic(op, ins)
	}
	if _, ok := amd64MaskUnpackBits[op]; ok {
		if rawOp != op {
			return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, op, ins.Raw)
		}
		return true, false, c.lowerMaskUnpack(op, ins)
	}
	if _, ok := amd64TernaryLogicSpecs[op]; ok {
		return c.lowerTernaryLogic(rawOp, ins)
	}
	if _, ok := amd64VectorAlignSpecs[op]; ok {
		return c.lowerVectorAlign(rawOp, ins)
	}
	if _, ok := amd64IFMASpecs[op]; ok {
		return c.lowerIFMA(rawOp, ins)
	}
	if _, ok := amd64FunnelShiftSpecs[op]; ok {
		return c.lowerFunnelShift(rawOp, ins)
	}
	if _, ok := amd64PackedRotateSpecs[op]; ok {
		return c.lowerPackedRotate(rawOp, ins)
	}
	if _, ok := amd64FMA3Specs[op]; ok {
		return c.lowerFMA3(rawOp, ins)
	}
	if _, ok := amd64BinaryFloatingSpecs[op]; ok {
		return c.lowerBinaryFloating(rawOp, ins)
	}
	if _, ok := amd64HorizontalFloatingSpecs[op]; ok {
		return c.lowerHorizontalFloating(rawOp, ins)
	}
	switch op {
	case "MOVOU", "MOVOA", "MOVUPS", "MOVAPS", "MOVO", "MOVQ", "VMOVQ", "MOVL", "MOVD",
		"VMOVDQU", "VMOVDQA", "VMOVNTDQ", "VMOVDQU64", "VMOVDQA64", "VMOVAPS", "VMOVAPD",
		"VPCMPEQB", "VPCMPGTB", "VPMOVMSKB", "VZEROUPPER", "VZEROALL", "VPBROADCASTB", "VPBROADCASTD", "VPBROADCASTQ", "VPAND", "VPXOR", "VPOR", "VPADDD", "VPADDQ", "VPSUBB", "VPTEST", "VTESTPD", "VTESTPS",
		"VPCLMULQDQ", "VEXTRACTF32X4",
		"VPCMPUQ",
		"VBROADCASTF32X2", "VBROADCASTSD",
		"VPSHUFB", "VPSHUFD", "VPSLLD", "VPSLLQ", "VPSLLW", "VPSRAD", "VPSRAW", "VPSRLD", "VPSRLQ", "VPSRLW", "VPSRLDQ", "VPSLLDQ", "VPUNPCKLBW", "VPUNPCKHBW", "VPUNPCKLDQ", "VPUNPCKHDQ", "VPUNPCKLQDQ", "VPUNPCKHQDQ",
		"VPALIGNR", "VPERM2I128", "VPERM2F128", "VINSERTI128", "VPBLENDD",
		"PXOR", "POR", "PAND", "PADDB", "PADDD", "PADDL", "PSUBB", "PSUBL", "PSUBUSB", "PMULLW", "PCLMULQDQ", "PCMPEQB", "PCMPEQW", "PCMPEQL", "PCMPGTB", "PABSD", "PTEST", "PMOVMSKB",
		"PMINUB", "PMINSB", "PMINUW", "PMINSW", "PMINUD", "PMINSD", "PMAXUB", "PMAXSB", "PMAXUW", "PMAXSW", "PMAXUD", "PMAXSD",
		"PSHUFB", "PSRLDQ", "PSLLDQ", "PSRLO", "PSLLO", "PSRLQ", "PSLLQ", "PSLLW", "PSRLW", "PSRLL", "PSLLL", "PSRAL", "PEXTRD", "PEXTRB", "PEXTRQ",
		"PALIGNR", "PUNPCKLBW", "PUNPCKHBW", "PUNPCKLLQ", "PUNPCKHLQ", "PUNPCKLQDQ", "PUNPCKHQDQ", "PSHUFL", "PSHUFD", "SHUFPS",
		"PBLENDW", "PADDQ",
		"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC", "AESKEYGENASSIST":
		// ok
	default:
		return false, false, nil
	}

	if op == "VMOVDQA" {
		op = "VMOVDQU"
	}
	if op == "VMOVDQA64" {
		op = "VMOVDQU64"
	}
	if op == "PSLLO" {
		op = "PSLLDQ"
	}
	if op == "PSRLO" {
		op = "PSRLDQ"
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

	switch op {
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

	case "VPBROADCASTD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPBROADCASTD expects scalar src, vector dst: %q", ins.Raw)
		}
		var low32 string
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseXReg(ins.Args[0].Reg); ok {
				value, err := c.loadX(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				words := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", words, value)
				extracted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %%%s, i32 0\n", extracted, words)
				low32 = "%" + extracted
			}
		}
		if low32 == "" {
			var value64 string
			var err error
			switch ins.Args[0].Kind {
			case OpMem:
				addr, addrErr := c.addrFromMem(ins.Args[0].Mem)
				if addrErr != nil {
					return true, false, addrErr
				}
				loaded := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", loaded, c.ptrFromAddrI64(addr))
				low32 = "%" + loaded
			case OpSym:
				p, ptrErr := c.ptrFromSB(ins.Args[0].Sym)
				if ptrErr != nil {
					return true, false, ptrErr
				}
				loaded := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", loaded, p)
				low32 = "%" + loaded
			default:
				value64, err = c.evalI64(ins.Args[0])
				if err != nil {
					return true, false, err
				}
			}
			if low32 == "" {
				truncated := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncated, value64)
				low32 = "%" + truncated
			}
		}
		lanes := 0
		store := func(string) error { return nil }
		switch {
		case isAMD64XReg(ins.Args[1].Reg):
			lanes = 4
			store = func(value string) error {
				bytesValue := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %s to <16 x i8>\n", bytesValue, value)
				return c.storeX(ins.Args[1].Reg, "%"+bytesValue)
			}
		case isAMD64YReg(ins.Args[1].Reg):
			lanes = 8
			store = func(value string) error {
				bytesValue := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i32> %s to <32 x i8>\n", bytesValue, value)
				return c.storeY(ins.Args[1].Reg, "%"+bytesValue)
			}
		case isAMD64ZReg(ins.Args[1].Reg):
			lanes = 16
			store = func(value string) error {
				bytesValue := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i32> %s to <64 x i8>\n", bytesValue, value)
				return c.storeZ(ins.Args[1].Reg, "%"+bytesValue)
			}
		default:
			return false, false, nil
		}
		seed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i32> zeroinitializer, i32 %s, i32 0\n", seed, lanes, low32)
		mask := make([]string, lanes)
		for i := range mask {
			mask[i] = "i32 0"
		}
		broadcast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i32> %%%s, <%d x i32> zeroinitializer, <%d x i32> <%s>\n", broadcast, lanes, seed, lanes, lanes, strings.Join(mask, ", "))
		return true, false, store("%" + broadcast)

	case "VBROADCASTF32X2", "VBROADCASTSD", "VPBROADCASTQ":
		// These instructions broadcast the low 64 source bits. Their lane
		// interpretation differs, but the resulting byte pattern is identical.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects scalar src, vector dst: %q", op, ins.Raw)
		}
		dstIsX := false
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); ok {
			dstIsX = true
			if op != "VPBROADCASTQ" {
				return false, false, nil
			}
		} else if _, ok := amd64ParseYReg(ins.Args[1].Reg); !ok {
			if _, ok := amd64ParseZReg(ins.Args[1].Reg); !ok {
				return false, false, nil
			}
		}
		if ins.Args[0].Kind == OpImm {
			return false, false, nil
		}
		if ins.Args[0].Kind == OpSym && strings.HasPrefix(strings.TrimSpace(ins.Args[0].Sym), "$") {
			return false, false, nil
		}
		var v64 string
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseXReg(ins.Args[0].Reg); ok {
				xv, err := c.loadX(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				words := c.newTmp()
				low := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", words, xv)
				fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", low, words)
				v64 = "%" + low
			} else if op != "VPBROADCASTQ" {
				return false, false, nil
			}
		}
		if v64 == "" {
			var err error
			v64, err = c.evalI64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
		}
		chunk := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <8 x i8>\n", chunk, v64)
		if dstIsX {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i8> %%%s, <8 x i8> %%%s, <16 x i32> %s\n", out, chunk, chunk, llvmRepeatI8Mask(8, 16))
			return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
		}
		if _, ok := amd64ParseYReg(ins.Args[1].Reg); ok {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i8> %%%s, <8 x i8> %%%s, <32 x i32> %s\n", out, chunk, chunk, llvmRepeatI8Mask(8, 32))
			return true, false, c.storeY(ins.Args[1].Reg, "%"+out)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <8 x i8> %%%s, <8 x i8> %%%s, <64 x i32> %s\n", out, chunk, chunk, llvmRepeatI8Mask(8, 64))
		return true, false, c.storeZ(ins.Args[1].Reg, "%"+out)

	case "VPSLLD", "VPSLLQ", "VPSLLW", "VPSRAD", "VPSRAW", "VPSRLD", "VPSRLQ", "VPSRLW":
		// Go's x86 assembler uses _yvpslld for this whole family:
		//   $imm8, X|Y|Z src/mem, [Kmask,] X|Y|Z dst
		//   X|m128 count, X|Y|Z src, [Kmask,] X|Y|Z dst
		// The count is uniform: variable forms use the low 64 bits of X|m128.
		if (len(ins.Args) != 3 && len(ins.Args) != 4) || ins.Args[len(ins.Args)-1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects count, vector src, [K mask,] vector dst: %q", op, ins.Raw)
		}
		dst := ins.Args[len(ins.Args)-1].Reg
		byteWidth := 0
		var src string
		var err error
		loadDst := func() (string, error) { return "", nil }
		store := func(string) error { return nil }
		switch {
		case isAMD64XReg(dst):
			byteWidth = 16
			src, err = c.loadXVecOperand(ins.Args[1])
			loadDst = func() (string, error) { return c.loadX(dst) }
			store = func(v string) error { return c.storeX(dst, v) }
		case isAMD64YReg(dst):
			byteWidth = 32
			src, err = c.loadYVecOperand(ins.Args[1])
			loadDst = func() (string, error) { return c.loadY(dst) }
			store = func(v string) error { return c.storeY(dst, v) }
		case isAMD64ZReg(dst):
			byteWidth = 64
			src, err = c.loadZVecOperand(ins.Args[1])
			loadDst = func() (string, error) { return c.loadZ(dst) }
			store = func(v string) error { return c.storeZ(dst, v) }
		default:
			return false, false, nil
		}
		if err != nil {
			return true, false, err
		}

		elemBits := 32
		switch op[len(op)-1] {
		case 'Q':
			elemBits = 64
		case 'W':
			elemBits = 16
		}
		lanes := byteWidth * 8 / elemBits
		vecType := fmt.Sprintf("<%d x i%d>", lanes, elemBits)
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", bc, byteWidth, src, vecType)

		llvmOp := "shl"
		arithmetic := op == "VPSRAD" || op == "VPSRAW"
		if arithmetic {
			llvmOp = "ashr"
		} else if strings.HasPrefix(string(op), "VPSRL") {
			llvmOp = "lshr"
		}

		shifted := "zeroinitializer"
		if ins.Args[0].Kind == OpImm {
			count := uint64(ins.Args[0].Imm) & 0xff
			if arithmetic && count >= uint64(elemBits) {
				count = uint64(elemBits - 1)
			}
			if arithmetic || count < uint64(elemBits) {
				sh := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %s\n", sh, llvmOp, vecType, bc, llvmSplatInteger(lanes, elemBits, count))
				shifted = "%" + sh
			}
		} else {
			countVec, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, fmt.Errorf("amd64 %s count: %w", op, err)
			}
			countWords := c.newTmp()
			count := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", countWords, countVec)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", count, countWords)
			inRange := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %d\n", inRange, count, elemBits)
			safeCount := c.newTmp()
			fallback := 0
			if arithmetic {
				fallback = elemBits - 1
			}
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %d\n", safeCount, inRange, count, fallback)
			shiftCount := "%" + safeCount
			if elemBits < 64 {
				truncated := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i%d\n", truncated, safeCount, elemBits)
				shiftCount = "%" + truncated
			}
			countSplat := amd64SplatInteger(c, lanes, elemBits, shiftCount)
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %s\n", sh, llvmOp, vecType, bc, countSplat)
			shifted = "%" + sh
			if !arithmetic {
				condition := amd64SplatI1(c, lanes, "%"+inRange)
				selected := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %s, %s %s, %s zeroinitializer\n", selected, lanes, condition, vecType, shifted, vecType)
				shifted = "%" + selected
			}
		}

		if len(ins.Args) == 4 {
			if ins.Args[2].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 %s masked form expects K mask: %q", op, ins.Raw)
			}
			if _, ok := amd64ParseKReg(ins.Args[2].Reg); !ok {
				return false, false, nil
			}
			maskValue, err := c.loadK(ins.Args[2].Reg)
			if err != nil {
				return true, false, err
			}
			oldBytes, err := loadDst()
			if err != nil {
				return true, false, err
			}
			old := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", old, byteWidth, oldBytes, vecType)
			shifted = amd64ApplyIntegerLaneMask(c, lanes, elemBits, shifted, "%"+old, maskValue, zeroMasking)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, vecType, shifted, byteWidth)
		return true, false, store("%" + out)

	case "VPALIGNR":
		return c.lowerPackedAlignRight(rawOp, ins)

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
		// Compatibility entry point for direct lowerVec unit tests. Ordinary
		// translation dispatches the whole family through the dedicated
		// lowerer before reaching this legacy switch.
		return c.lowerNonTemporalVectorMove(op, ins)

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

	case "PTEST", "VPTEST", "VTESTPD", "VTESTPS":
		return c.lowerVectorTest(rawOp, ins)

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
		return c.lowerPackedByteShift(rawOp, ins)

	case "VPUNPCKLBW", "VPUNPCKHBW":
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src1, src2, dst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); ok {
			for _, arg := range ins.Args[:2] {
				if arg.Kind == OpReg {
					if _, ok := amd64ParseXReg(arg.Reg); !ok {
						return false, false, nil
					}
				}
			}
			a, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadXVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			start := 0
			if op == "VPUNPCKHBW" {
				start = 8
			}
			mask := make([]string, 0, 16)
			for i := start; i < start+8; i++ {
				mask = append(mask, fmt.Sprintf("i32 %d", i), fmt.Sprintf("i32 %d", 16+i))
			}
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, <16 x i32> <%s>\n", sh, b, a, strings.Join(mask, ", "))
			return true, false, c.storeX(ins.Args[2].Reg, "%"+sh)
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); ok {
			for _, arg := range ins.Args[:2] {
				if arg.Kind == OpReg {
					if _, ok := amd64ParseYReg(arg.Reg); !ok {
						return false, false, nil
					}
				}
			}
			a, err := c.loadYVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadYVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			start := 0
			if op == "VPUNPCKHBW" {
				start = 8
			}
			mask := make([]string, 0, 32)
			for lane := 0; lane < 2; lane++ {
				for i := start; i < start+8; i++ {
					idx := lane*16 + i
					mask = append(mask, fmt.Sprintf("i32 %d", idx), fmt.Sprintf("i32 %d", 32+idx))
				}
			}
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <32 x i8> %s, <32 x i8> %s, <32 x i32> <%s>\n", sh, b, a, strings.Join(mask, ", "))
			return true, false, c.storeY(ins.Args[2].Reg, "%"+sh)
		}
		return false, false, nil

	case "PUNPCKLBW", "PUNPCKHBW":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
				return false, false, nil
			}
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		start := 0
		if op == "PUNPCKHBW" {
			start = 8
		}
		maskParts := make([]string, 0, 16)
		for i := start; i < start+8; i++ {
			maskParts = append(maskParts, fmt.Sprintf("i32 %d", i), fmt.Sprintf("i32 %d", 16+i))
		}
		mask := "<16 x i32> <" + strings.Join(maskParts, ", ") + ">"
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> %s, %s\n", sh, dstv, src, mask)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+sh)

	case "PUNPCKLLQ", "PUNPCKHLQ":
		// PUNPCKL/H LQ interleaves the low/high pair of 32-bit lanes.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc/m128, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
				return false, false, nil
			}
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		dst32 := c.newTmp()
		src32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", dst32, dstv)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", src32, src)
		mask := "<4 x i32> <i32 0, i32 4, i32 1, i32 5>"
		if op == "PUNPCKHLQ" {
			mask = "<4 x i32> <i32 2, i32 6, i32 3, i32 7>"
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i32> %%%s, <4 x i32> %%%s, %s\n", sh, dst32, src32, mask)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, sh)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "PUNPCKLQDQ":
		// PUNPCKLQDQ Xsrc/m128, Xdst interleaves the low quadwords:
		// dst = {dst[63:0], src[63:0]}.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PUNPCKLQDQ expects Xsrc/m128, Xdst: %q", ins.Raw)
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
		dstQ := c.newTmp()
		srcQ := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", dstQ, dstv)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", srcQ, src)
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %%%s, <2 x i64> %%%s, <2 x i32> <i32 0, i32 2>\n", sh, dstQ, srcQ)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, sh)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "PUNPCKHQDQ":
		// PUNPCKHQDQ Xsrc/m128, Xdst interleaves the high quadwords:
		// dst = {dst[127:64], src[127:64]}.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PUNPCKHQDQ expects Xsrc/m128, Xdst: %q", ins.Raw)
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
		dstQ := c.newTmp()
		srcQ := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", dstQ, dstv)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", srcQ, src)
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %%%s, <2 x i64> %%%s, <2 x i32> <i32 1, i32 3>\n", sh, dstQ, srcQ)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, sh)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "VPUNPCKLDQ", "VPUNPCKHDQ", "VPUNPCKLQDQ", "VPUNPCKHQDQ":
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src1, src2, dst: %q", op, ins.Raw)
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
			laneType := "i64"
			lanes := 2
			mask := "<i32 1, i32 3>"
			if op == "VPUNPCKLQDQ" {
				mask = "<i32 0, i32 2>"
			} else if op == "VPUNPCKLDQ" {
				laneType, lanes = "i32", 4
				mask = "<i32 0, i32 4, i32 1, i32 5>"
			} else if op == "VPUNPCKHDQ" {
				laneType, lanes = "i32", 4
				mask = "<i32 2, i32 6, i32 3, i32 7>"
			}
			aq := c.newTmp()
			bq := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x %s>\n", aq, a, lanes, laneType)
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x %s>\n", bq, b, lanes, laneType)
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> %%%s, <%d x i32> %s\n", sh, lanes, laneType, bq, lanes, laneType, aq, lanes, mask)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %%%s to <16 x i8>\n", out, lanes, laneType, sh)
			return true, false, c.storeX(ins.Args[2].Reg, "%"+out)
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
			laneType := "i64"
			lanes := 4
			mask := "<i32 1, i32 5, i32 3, i32 7>"
			if op == "VPUNPCKLQDQ" {
				mask = "<i32 0, i32 4, i32 2, i32 6>"
			} else if op == "VPUNPCKLDQ" {
				laneType, lanes = "i32", 8
				mask = "<i32 0, i32 8, i32 1, i32 9, i32 4, i32 12, i32 5, i32 13>"
			} else if op == "VPUNPCKHDQ" {
				laneType, lanes = "i32", 8
				mask = "<i32 2, i32 10, i32 3, i32 11, i32 6, i32 14, i32 7, i32 15>"
			}
			aq := c.newTmp()
			bq := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <%d x %s>\n", aq, a, lanes, laneType)
			fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <%d x %s>\n", bq, b, lanes, laneType)
			sh := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> %%%s, <%d x i32> %s\n", sh, lanes, laneType, bq, lanes, laneType, aq, lanes, mask)
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %%%s to <32 x i8>\n", out, lanes, laneType, sh)
			return true, false, c.storeY(ins.Args[2].Reg, "%"+out)
		}
		return false, false, nil

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

	case "VPCMPEQB", "VPCMPGTB":
		// Three-operand packed-byte comparison. Go syntax lists the Intel
		// r/m source first, so the result is src2 ==|> src1.
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src1, src2, dst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseYReg(ins.Args[2].Reg); ok {
			for _, arg := range ins.Args[:2] {
				if arg.Kind == OpReg {
					if _, ok := amd64ParseYReg(arg.Reg); !ok {
						return false, false, nil
					}
				}
			}
			a, err := c.loadYVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadYVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			pred := "eq"
			if op == "VPCMPGTB" {
				pred = "sgt"
			}
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %s <32 x i8> %s, %s\n", cmp, pred, b, a)
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select <32 x i1> %%%s, <32 x i8> %s, <32 x i8> zeroinitializer\n", sel, cmp, llvmAllOnesI8Vec(32))
			return true, false, c.storeY(ins.Args[2].Reg, "%"+sel)
		}
		if _, ok := amd64ParseXReg(ins.Args[2].Reg); ok {
			for _, arg := range ins.Args[:2] {
				if arg.Kind == OpReg {
					if _, ok := amd64ParseXReg(arg.Reg); !ok {
						return false, false, nil
					}
				}
			}
			a, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			b, err := c.loadXVecOperand(ins.Args[1])
			if err != nil {
				return true, false, err
			}
			pred := "eq"
			if op == "VPCMPGTB" {
				pred = "sgt"
			}
			cmp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %s <16 x i8> %s, %s\n", cmp, pred, b, a)
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select <16 x i1> %%%s, <16 x i8> %s, <16 x i8> zeroinitializer\n", sel, cmp, llvmAllOnesI8Vec(16))
			return true, false, c.storeX(ins.Args[2].Reg, "%"+sel)
		}
		return false, false, nil

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

	case "PABSD":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 PABSD expects Xsrc, Xdst: %q", ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		src, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		values := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", values, src)
		negative := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt <4 x i32> %%%s, zeroinitializer\n", negative, values)
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub <4 x i32> zeroinitializer, %%%s\n", negated, values)
		absolute := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <4 x i1> %%%s, <4 x i32> %%%s, <4 x i32> %%%s\n", absolute, negative, negated, values)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, absolute)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "PMINUB", "PMINSB", "PMINUW", "PMINSW", "PMINUD", "PMINSD",
		"PMAXUB", "PMAXSB", "PMAXUW", "PMAXSW", "PMAXUD", "PMAXSD":
		return c.lowerPackedIntegerMinMax(rawOp, ins)

	case "PSLLW", "PSRLW", "PSLLL", "PSRLL", "PSRAL":
		// Two-operand packed integer shift immediate.
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		laneBits := int64(32)
		vecTy := "<4 x i32>"
		if op == "PSLLW" || op == "PSRLW" {
			laneBits = 16
			vecTy = "<8 x i16>"
		}
		n := ins.Args[0].Imm
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, v, vecTy)
		if n < 0 {
			return true, false, fmt.Errorf("amd64 %s shift count must be non-negative: %q", op, ins.Raw)
		}
		if n >= laneBits {
			if op != "PSRAL" {
				return true, false, c.storeX(ins.Args[1].Reg, "zeroinitializer")
			}
			// Packed arithmetic right shifts saturate an oversized count to
			// laneBits-1, producing an all-sign-bit lane instead of zero.
			n = laneBits - 1
		}
		sh := c.newTmp()
		switch op {
		case "PSLLW":
			fmt.Fprintf(c.b, "  %%%s = shl <8 x i16> %%%s, <i16 %d, i16 %d, i16 %d, i16 %d, i16 %d, i16 %d, i16 %d, i16 %d>\n", sh, bc, n, n, n, n, n, n, n, n)
		case "PSRLW":
			fmt.Fprintf(c.b, "  %%%s = lshr <8 x i16> %%%s, <i16 %d, i16 %d, i16 %d, i16 %d, i16 %d, i16 %d, i16 %d, i16 %d>\n", sh, bc, n, n, n, n, n, n, n, n)
		case "PSLLL":
			fmt.Fprintf(c.b, "  %%%s = shl <4 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n)
		case "PSRLL":
			fmt.Fprintf(c.b, "  %%%s = lshr <4 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n)
		case "PSRAL":
			fmt.Fprintf(c.b, "  %%%s = ashr <4 x i32> %%%s, <i32 %d, i32 %d, i32 %d, i32 %d>\n", sh, bc, n, n, n, n)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecTy, sh)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "PCMPEQW", "PCMPEQL":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects Xsrc, Xdst: %q", op, ins.Raw)
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
		laneType := "i32"
		lanes := 4
		if op == "PCMPEQW" {
			laneType = "i16"
			lanes = 8
		}
		vecType := fmt.Sprintf("<%d x %s>", lanes, laneType)
		as := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", as, src, vecType)
		bs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bs, dstv, vecType)
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, %%%s\n", cmp, vecType, bs, as)
		sext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", sext, lanes, cmp, vecType)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, vecType, sext)
		return true, false, c.storeX(ins.Args[1].Reg, "%"+out)

	case "VPCLMULQDQ":
		return c.lowerPackedCarrylessMultiply(rawOp, ins)

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
		return c.lowerPackedCarrylessMultiply(rawOp, ins)

	case "PCMPEQB", "PCMPGTB":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseXReg(ins.Args[0].Reg); !ok {
				return false, false, nil
			}
		}
		allOnes := llvmAllOnesI8Vec(16)
		// Common idiom: PCMPEQB X3, X3 -> all ones.
		if op == "PCMPEQB" && ins.Args[0].Kind == OpReg && ins.Args[0].Reg == ins.Args[1].Reg {
			return true, false, c.storeX(ins.Args[1].Reg, allOnes)
		}
		srcv, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dstv, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		cmp := c.newTmp()
		pred := "eq"
		if op == "PCMPGTB" {
			pred = "sgt"
		}
		fmt.Fprintf(c.b, "  %%%s = icmp %s <16 x i8> %s, %s\n", cmp, pred, dstv, srcv)
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
		return c.lowerPackedAlignRight(rawOp, ins)

	case "PSRLDQ", "PSLLDQ":
		return c.lowerPackedByteShift(rawOp, ins)

	case "PSRLQ", "PSLLQ":
		// PSR/LLQ $imm, Xdst (shift each 64-bit lane). Counts at or above
		// the lane width clear the destination rather than wrapping modulo 64.
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects $imm, Xdst: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
			return false, false, nil
		}
		n := ins.Args[0].Imm
		if n < 0 {
			return true, false, fmt.Errorf("amd64 %s shift count must be non-negative: %q", op, ins.Raw)
		}
		if n >= 64 {
			return true, false, c.storeX(ins.Args[1].Reg, "zeroinitializer")
		}
		v, err := c.loadX(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, v)
		sh := c.newTmp()
		shiftOp := "lshr"
		if op == "PSLLQ" {
			shiftOp = "shl"
		}
		fmt.Fprintf(c.b, "  %%%s = %s <2 x i64> %%%s, <i64 %d, i64 %d>\n", sh, shiftOp, bc, n, n)
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

func (c *amd64Ctx) validateMOVDAliasForm(ins Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("%s MOVD expects 2 operands: %q", c.goarch, ins.Raw)
	}
	src, dst := ins.Args[0], ins.Args[1]
	srcMem, dstMem := isAMD64MemoryOperand(src), isAMD64MemoryOperand(dst)
	srcX, dstX := isAMD64MOVDXRegister(src), isAMD64MOVDXRegister(dst)
	srcM, dstM := isAMD64MOVDMRegister(src), isAMD64MOVDMRegister(dst)
	srcGP, dstGP := c.isGoYrlRegister(src), c.isGoYrlRegister(dst)
	srcAddress := x86GoMOVQAddressSource(src, c.goarch)

	valid := false
	if c.goarch == "386" {
		// In 32-bit mode AMOVQ has only its memory/MMX/XMM rows. Go rejects
		// every GP and immediate form as an illegal 64-bit instruction.
		valid = (dstMem && (srcX || srcM)) ||
			(dstX && (srcMem || srcX)) ||
			(dstM && (srcMem || srcX))
	} else {
		valid = (dstGP && (src.Kind == OpImm || srcAddress || srcGP || srcMem || srcX || srcM)) ||
			(dstMem && (src.Kind == OpImm || srcGP || srcX || srcM)) ||
			(dstX && (srcGP || srcMem || srcX)) ||
			(dstM && (srcGP || srcMem || srcX || srcM))
	}
	if !valid {
		return fmt.Errorf("%s MOVD operands are outside Go 1.27's MOVD/ymovq forms: %q", c.goarch, ins.Raw)
	}
	return nil
}

func isAMD64MOVDXRegister(op Operand) bool {
	if op.Kind != OpReg {
		return false
	}
	_, ok := amd64ParseXReg(op.Reg)
	return ok
}

func isAMD64MOVDMRegister(op Operand) bool {
	if op.Kind != OpReg {
		return false
	}
	_, ok := amd64ParseMReg(op.Reg)
	return ok
}

func (c *amd64Ctx) isGoYrlRegister(op Operand) bool {
	if op.Kind != OpReg || !isAMD64YrlRegister(op.Reg) {
		return false
	}
	if c.goarch != "386" {
		return true
	}
	switch op.Reg {
	case AX, BX, CX, DX, SP, BP, SI, DI:
		return true
	default:
		return false
	}
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

func llvmSplatInteger(lanes, bits int, value uint64) string {
	return llvmSplatIntegerText(lanes, bits, strconv.FormatUint(value, 10))
}

func llvmSplatIntegerText(lanes, bits int, value string) string {
	if lanes <= 0 {
		return "<>"
	}
	element := "i" + strconv.Itoa(bits) + " " + value
	var b strings.Builder
	// The two brackets replace the separator omitted before the first lane.
	b.Grow(lanes * (len(element) + 2))
	b.WriteByte('<')
	for lane := 0; lane < lanes; lane++ {
		if lane != 0 {
			b.WriteString(", ")
		}
		b.WriteString(element)
	}
	b.WriteByte('>')
	return b.String()
}

func amd64SplatInteger(c *amd64Ctx, lanes, bits int, value string) string {
	seed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> poison, i%d %s, i32 0\n", seed, lanes, bits, bits, value)
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %%%s, <%d x i%d> poison, <%d x i32> zeroinitializer\n", splat, lanes, bits, seed, lanes, bits, lanes)
	return "%" + splat
}

func amd64SplatI1(c *amd64Ctx, lanes int, value string) string {
	seed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i1> poison, i1 %s, i32 0\n", seed, lanes, value)
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i1> %%%s, <%d x i1> poison, <%d x i32> zeroinitializer\n", splat, lanes, seed, lanes, lanes)
	return "%" + splat
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

func isAMD64XReg(r Reg) bool {
	_, ok := amd64ParseXReg(r)
	return ok
}

func isAMD64YReg(r Reg) bool {
	_, ok := amd64ParseYReg(r)
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

func amd64ApplyI32LaneMask(c *amd64Ctx, lanes int, computed, old, mask string, zeroing bool) string {
	return amd64ApplyIntegerLaneMask(c, lanes, 32, computed, old, mask, zeroing)
}

func amd64ApplyIntegerLaneMask(c *amd64Ctx, lanes, bits int, computed, old, mask string, zeroing bool) string {
	fallback := old
	if zeroing {
		fallback = "zeroinitializer"
	}
	if lanes <= 0 {
		return fallback
	}

	// Each predicate lane selects its own numerical mask bit. A scalar-to-
	// vector bitcast would instead depend on the target's byte order. Typed
	// callers supply at most 64 lanes, so every logical shift is below 64.
	splat := amd64SplatInteger(c, lanes, 64, mask)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr <%d x i64> %s, <", shifted, lanes, splat)
	for lane := 0; lane < lanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i64 %d", lane)
	}
	c.b.WriteString(">\n")
	predicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc <%d x i64> %%%s to <%d x i1>\n", predicate, lanes, shifted, lanes)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %s\n",
		selected, lanes, predicate, lanes, bits, computed, lanes, bits, fallback)
	return "%" + selected
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
