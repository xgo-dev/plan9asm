package plan9asm

import (
	"fmt"
	"strings"
)

// lowerDwordToQwordMultiply implements PMULDQ, PMULULQ, VPMULDQ, and
// VPMULUDQ across their complete Go 1.27 yxm_q4/ymm/_yvandnpd forms.
func (c *amd64Ctx) lowerDwordToQwordMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	signed := false
	vector := false
	switch baseOp {
	case "PMULDQ":
		signed = true
	case "PMULULQ":
	case "VPMULDQ":
		signed, vector = true, true
	case "VPMULUDQ":
		vector = true
	default:
		return false, false, nil
	}

	broadcast, zeroing := false, false
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		for i, suffix := range strings.Split(rawOp[dot+1:], ".") {
			switch suffix {
			case "BCST":
				if !vector || broadcast || zeroing {
					return true, false, fmt.Errorf("amd64 %s has invalid .BCST suffix: %q", baseOp, ins.Raw)
				}
				broadcast = true
			case "Z":
				if !vector || zeroing || i != len(strings.Split(rawOp[dot+1:], "."))-1 {
					return true, false, fmt.Errorf("amd64 %s has invalid .Z suffix: %q", baseOp, ins.Raw)
				}
				zeroing = true
			default:
				return true, false, fmt.Errorf("amd64 %s has unsupported suffix .%s: %q", baseOp, suffix, ins.Raw)
			}
		}
	}
	if !vector {
		return c.lowerLegacyDwordToQwordMultiply(baseOp, signed, ins)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects source, source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires K1-K7: %q", baseOp, ins.Raw)
	}
	if broadcast && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s .BCST requires a memory first source: %q", baseOp, ins.Raw)
	}
	dst := ins.Args[len(ins.Args)-1]
	if dst.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects a vector destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dst.Reg)
	if byteWidth == 0 {
		return true, false, fmt.Errorf("amd64 %s expects an X, Y, or Z destination: %q", baseOp, ins.Raw)
	}
	if ins.Args[1].Kind != OpReg || amd64VectorByteWidth(ins.Args[1].Reg) != byteWidth {
		return true, false, fmt.Errorf("amd64 %s second source must match destination width: %q", baseOp, ins.Raw)
	}
	if !broadcast && ins.Args[0].Kind == OpReg && amd64VectorByteWidth(ins.Args[0].Reg) != byteWidth {
		return true, false, fmt.Errorf("amd64 %s first source must match destination width: %q", baseOp, ins.Raw)
	}
	if !broadcast && ins.Args[0].Kind != OpReg && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s first source must be vector or memory: %q", baseOp, ins.Raw)
	}

	lhs, err := c.loadDwordMultiplyEvenLanes(ins.Args[0], byteWidth, broadcast)
	if err != nil {
		return true, false, err
	}
	rhs, err := c.loadDwordMultiplyEvenLanes(ins.Args[1], byteWidth, false)
	if err != nil {
		return true, false, err
	}
	qwordLanes := byteWidth / 8
	lhs = c.extendDwordMultiplyLanes(lhs, qwordLanes, signed)
	rhs = c.extendDwordMultiplyLanes(rhs, qwordLanes, signed)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul <%d x i64> %s, %s\n", product, qwordLanes, lhs, rhs)
	result := "%" + product

	if masked {
		maskArg := ins.Args[2]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err := c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(dst, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, qwordLanes, 64, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, qwordLanes, 64, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", out, qwordLanes, result, byteWidth)
	return true, false, c.storeVectorBytes(dst.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) lowerLegacyDwordToQwordMultiply(op string, signed bool, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects source and X/MMX destination: %q", op, ins.Raw)
	}
	dst := ins.Args[1]
	if isAMD64XReg(dst.Reg) {
		if ins.Args[0].Kind == OpReg && !isAMD64XReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("amd64 %s X form requires X-or-memory source: %q", op, ins.Raw)
		}
		if !isAMD64XRegOperand(ins.Args[0]) && !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("amd64 %s X form requires X-or-memory source: %q", op, ins.Raw)
		}
		lhs, err := c.loadDwordMultiplyEvenLanes(ins.Args[0], 16, false)
		if err != nil {
			return true, false, err
		}
		rhs, err := c.loadDwordMultiplyEvenLanes(dst, 16, false)
		if err != nil {
			return true, false, err
		}
		lhs = c.extendDwordMultiplyLanes(lhs, 2, signed)
		rhs = c.extendDwordMultiplyLanes(rhs, 2, signed)
		product := c.newTmp()
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul <2 x i64> %s, %s\n", product, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, product)
		return true, false, c.storeX(dst.Reg, "%"+out)
	}
	if _, ok := amd64ParseMReg(dst.Reg); !ok || op != "PMULULQ" {
		return true, false, fmt.Errorf("amd64 %s destination is outside its Go 1.27 table: %q", op, ins.Raw)
	}
	if c.goarch == "386" {
		return true, false, fmt.Errorf("386 PMULULQ MMX form is illegal in 32-bit mode: %q", ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if _, ok := amd64ParseMReg(ins.Args[0].Reg); !ok {
			return true, false, fmt.Errorf("amd64 PMULULQ MMX form requires MMX-or-memory source: %q", ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 PMULULQ MMX form requires MMX-or-memory source: %q", ins.Raw)
	}
	source, err := c.evalIntSized(ins.Args[0], I64)
	if err != nil {
		return true, false, err
	}
	destination, err := c.evalIntSized(dst, I64)
	if err != nil {
		return true, false, err
	}
	sourceLow := c.lowDwordFromI64(source)
	destinationLow := c.lowDwordFromI64(destination)
	sourceWide := c.extendDwordScalar(sourceLow, false)
	destinationWide := c.extendDwordScalar(destinationLow, false)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", product, sourceWide, destinationWide)
	return true, false, c.storeReg(dst.Reg, "%"+product)
}

func isAMD64XRegOperand(op Operand) bool {
	return op.Kind == OpReg && isAMD64XReg(op.Reg)
}

func (c *amd64Ctx) loadDwordMultiplyEvenLanes(op Operand, byteWidth int, broadcast bool) (string, error) {
	qwordLanes := byteWidth / 8
	if broadcast {
		value, err := c.evalIntSized(op, I64)
		if err != nil {
			return "", err
		}
		low := c.lowDwordFromI64(value)
		return amd64SplatInteger(c, qwordLanes, 32, low), nil
	}
	bytesValue, err := c.loadPackedCompareBytes(op, byteWidth)
	if err != nil {
		return "", err
	}
	dwordLanes := byteWidth / 4
	all := c.bitcastVectorBytesToIntegerLanes(byteWidth, dwordLanes, 32, bytesValue)
	mask := make([]string, qwordLanes)
	for i := range mask {
		mask[i] = fmt.Sprintf("i32 %d", i*2)
	}
	even := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i32> %s, <%d x i32> zeroinitializer, <%d x i32> <%s>\n", even, dwordLanes, all, dwordLanes, qwordLanes, strings.Join(mask, ", "))
	return "%" + even, nil
}

func (c *amd64Ctx) extendDwordMultiplyLanes(value string, lanes int, signed bool) string {
	extended := c.newTmp()
	op := "zext"
	if signed {
		op = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i32> %s to <%d x i64>\n", extended, op, lanes, value, lanes)
	return "%" + extended
}

func (c *amd64Ctx) lowDwordFromI64(value string) string {
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", low, value)
	return "%" + low
}

func (c *amd64Ctx) extendDwordScalar(value string, signed bool) string {
	extended := c.newTmp()
	op := "zext"
	if signed {
		op = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s i32 %s to i64\n", extended, op, value)
	return "%" + extended
}
