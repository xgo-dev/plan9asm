package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

func amd64ParseMReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "M") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "M"))
	if err != nil || n < 0 || n > 7 {
		return 0, false
	}
	return n, true
}

// lowerPackedFloatToDword implements both entries in Go's yxcvm1 table for
// CVTPS2PL and CVTTPS2PL: X/m -> X and X/m64 -> M.
func (c *amd64Ctx) lowerPackedFloatToDword(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "CVTPS2PL", "CVTTPS2PL":
		// handled below
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects X/m source and X or M destination: %q", baseOp, ins.Raw)
	}

	dst := ins.Args[1].Reg
	var source string
	if isAMD64XReg(dst) {
		bytesValue, err := c.loadXVecOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", cast, bytesValue)
		source = "%" + cast
	} else if _, ok := amd64ParseMReg(dst); ok {
		if ins.Args[0].Kind == OpReg {
			bytesValue, err := c.loadXVecOperand(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			all := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", all, bytesValue)
			source = "%" + all
		} else {
			bits, err := c.evalIntSized(ins.Args[0], I64)
			if err != nil {
				return true, false, err
			}
			low := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <2 x float>\n", low, bits)
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x float> %%%s, <2 x float> zeroinitializer, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", wide, low)
			source = "%" + wide
		}
	} else {
		return true, false, fmt.Errorf("amd64 %s expects X or M destination: %q", baseOp, ins.Raw)
	}
	if _, mmx := amd64ParseMReg(dst); mmx {
		if c.mmxConversionSlot == "" {
			return true, false, fmt.Errorf("amd64 %s has no MMX conversion scratch slot", baseOp)
		}
		// LLVM 22's SSE2 vector intrinsic requires +sse2 even for Go's
		// original SSE1/MMX encoding. Emit that encoding into one entry-block
		// scratch slot, then load the two result lanes as an ordinary i64.
		mnemonic := "cvtps2pi"
		if baseOp == "CVTTPS2PL" {
			mnemonic = "cvttps2pi"
		}
		assembly := mnemonic + " $1, %mm0; movq %mm0, ($0)"
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(ptr %s, <4 x float> %s)\n",
			assembly, "r,x,~{mm0},~{memory}", c.mmxConversionSlot, source)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 8\n", result, c.mmxConversionSlot)
		return true, false, c.storeReg(dst, "%"+result)
	}

	intrinsic := "llvm.x86.sse2.cvtps2dq"
	if baseOp == "CVTTPS2PL" {
		intrinsic = "llvm.x86.sse2.cvttps2dq"
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x i32> @%s(<4 x float> %s)\n", converted, intrinsic, source)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", bytesValue, converted)
	return true, false, c.storeX(dst, "%"+bytesValue)
}

// lowerPackedSingleToDouble implements every operand shape in Go 1.27's
// CVTPS2PD yxm and VCVTPS2PD _yvcvtph2ps tables. The widening itself is exact;
// SAE therefore only changes the accepted encoding, not the generated value.
func (c *amd64Ctx) lowerPackedSingleToDouble(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "CVTPS2PD", "VCVTPS2PD":
		// handled below
	default:
		return false, false, nil
	}

	broadcast := false
	suppressAllExceptions := false
	zeroMasking := false
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		suffixes := strings.Split(rawOp[dot+1:], ".")
		for i, suffix := range suffixes {
			switch suffix {
			case "BCST":
				if broadcast || suppressAllExceptions || zeroMasking || i != 0 {
					return true, false, fmt.Errorf("amd64 %s has invalid or duplicate .BCST suffix: %q", baseOp, ins.Raw)
				}
				broadcast = true
			case "SAE":
				if suppressAllExceptions || broadcast || zeroMasking || i != 0 {
					return true, false, fmt.Errorf("amd64 %s has invalid or duplicate .SAE suffix: %q", baseOp, ins.Raw)
				}
				suppressAllExceptions = true
			case "Z":
				if zeroMasking || i != len(suffixes)-1 {
					return true, false, fmt.Errorf("amd64 %s has invalid or duplicate .Z suffix: %q", baseOp, ins.Raw)
				}
				zeroMasking = true
			default:
				return true, false, fmt.Errorf("amd64 %s has unsupported suffix .%s: %q", baseOp, suffix, ins.Raw)
			}
		}
	}

	vectorForm := baseOp == "VCVTPS2PD"
	if !vectorForm {
		if rawOp != baseOp || len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 CVTPS2PD expects X/m64 source and X destination: %q", ins.Raw)
		}
	} else if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 VCVTPS2PD expects source, [K mask,] vector destination: %q", ins.Raw)
	}
	masked := vectorForm && len(ins.Args) == 3
	if zeroMasking && !masked {
		return true, false, fmt.Errorf("amd64 VCVTPS2PD .Z form requires a K mask: %q", ins.Raw)
	}
	if broadcast && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 VCVTPS2PD .BCST requires a memory source: %q", ins.Raw)
	}

	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects a vector destination: %q", baseOp, ins.Raw)
	}
	dst := dstArg.Reg
	lanes := 0
	byteWidth := 0
	var loadDst func() (string, error)
	var storeDst func(string) error
	switch {
	case isAMD64XReg(dst):
		lanes, byteWidth = 2, 16
		loadDst = func() (string, error) { return c.loadX(dst) }
		storeDst = func(value string) error { return c.storeX(dst, value) }
	case vectorForm && isAMD64YReg(dst):
		lanes, byteWidth = 4, 32
		loadDst = func() (string, error) { return c.loadY(dst) }
		storeDst = func(value string) error { return c.storeY(dst, value) }
	case vectorForm && isAMD64ZReg(dst):
		lanes, byteWidth = 8, 64
		loadDst = func() (string, error) { return c.loadZ(dst) }
		storeDst = func(value string) error { return c.storeZ(dst, value) }
	default:
		return true, false, fmt.Errorf("amd64 %s has mismatched or non-vector destination: %q", baseOp, ins.Raw)
	}

	srcArg := ins.Args[0]
	if suppressAllExceptions && (lanes != 8 || srcArg.Kind != OpReg) {
		return true, false, fmt.Errorf("amd64 VCVTPS2PD .SAE requires a Y register source and Z destination: %q", ins.Raw)
	}
	if srcArg.Kind == OpReg {
		valid := (lanes <= 4 && isAMD64XReg(srcArg.Reg)) || (lanes == 8 && isAMD64YReg(srcArg.Reg))
		if !valid {
			return true, false, fmt.Errorf("amd64 %s source width does not match destination: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(srcArg) {
		return true, false, fmt.Errorf("amd64 %s expects a vector register or memory source: %q", baseOp, ins.Raw)
	}

	var source string
	if broadcast {
		scalar, err := c.evalF32(srcArg)
		if err != nil {
			return true, false, err
		}
		seed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x float> poison, float %s, i32 0\n", seed, lanes, scalar)
		splat := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x float> %%%s, <%d x float> poison, <%d x i32> zeroinitializer\n", splat, lanes, seed, lanes, lanes)
		source = "%" + splat
	} else {
		switch lanes {
		case 2:
			if srcArg.Kind == OpReg {
				bytesValue, err := c.loadX(srcArg.Reg)
				if err != nil {
					return true, false, err
				}
				all := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", all, bytesValue)
				low := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x float> %%%s, <4 x float> poison, <2 x i32> <i32 0, i32 1>\n", low, all)
				source = "%" + low
			} else {
				bits, err := c.evalIntSized(srcArg, I64)
				if err != nil {
					return true, false, err
				}
				cast := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <2 x float>\n", cast, bits)
				source = "%" + cast
			}
		case 4:
			bytesValue, err := c.loadXVecOperand(srcArg)
			if err != nil {
				return true, false, err
			}
			cast := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", cast, bytesValue)
			source = "%" + cast
		case 8:
			bytesValue, err := c.loadYVecOperand(srcArg)
			if err != nil {
				return true, false, err
			}
			cast := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <8 x float>\n", cast, bytesValue)
			source = "%" + cast
		}
	}

	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fpext <%d x float> %s to <%d x double>\n", converted, lanes, source, lanes)
	result := "%" + converted
	if masked {
		maskArg := ins.Args[1]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VCVTPS2PD masked form expects K1-K7: %q", ins.Raw)
		}
		maskIndex, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 VCVTPS2PD masked form expects K1-K7: %q", ins.Raw)
		}
		mask, err := c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
		computedBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x double> %s to <%d x i64>\n", computedBits, lanes, result, lanes)
		oldBytes, err := loadDst()
		if err != nil {
			return true, false, err
		}
		oldBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", oldBits, byteWidth, oldBytes, lanes)
		maskedBits := amd64ApplyIntegerLaneMask(c, lanes, 64, "%"+computedBits, "%"+oldBits, mask, zeroMasking)
		maskedValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x double>\n", maskedValue, lanes, maskedBits, lanes)
		result = "%" + maskedValue
	}

	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x double> %s to <%d x i8>\n", out, lanes, result, byteWidth)
	return true, false, storeDst("%" + out)
}
