package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedDwordMultiply implements every operand shape in Go 1.27's
// PMULLD yxm_q4 and VPMULLD _yvandnpd tables, including EVEX masks and
// the memory broadcast enabled by evexBcstN4.
func (c *amd64Ctx) lowerPackedDwordMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := string(op)
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "PMULLD", "VPMULLD":
		// handled below
	default:
		return false, false, nil
	}
	zeroMasking := false
	broadcast := false
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		suffixes := strings.Split(rawOp[dot+1:], ".")
		for i, suffix := range suffixes {
			switch suffix {
			case "BCST":
				if broadcast || zeroMasking {
					return true, false, fmt.Errorf("amd64 %s has invalid suffix order or duplicate .BCST: %q", baseOp, ins.Raw)
				}
				broadcast = true
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
	vectorForm := baseOp == "VPMULLD"
	if (!vectorForm && len(ins.Args) != 2) || (vectorForm && len(ins.Args) != 3 && len(ins.Args) != 4) {
		return true, false, fmt.Errorf("amd64 %s expects src, [src, K mask,] vector dst: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if !vectorForm && (broadcast || zeroMasking) {
		return true, false, fmt.Errorf("amd64 PMULLD does not accept EVEX suffixes: %q", ins.Raw)
	}
	if zeroMasking && !masked {
		return true, false, fmt.Errorf("amd64 VPMULLD .Z form requires a K mask: %q", ins.Raw)
	}
	if broadcast && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 VPMULLD .BCST requires a memory source: %q", ins.Raw)
	}

	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects vector destination: %q", baseOp, ins.Raw)
	}
	byteWidth := 0
	var loadOperand func(Operand) (string, error)
	var loadDst func() (string, error)
	var storeDst func(string) error
	switch {
	case isAMD64XReg(dstArg.Reg):
		byteWidth = 16
		loadOperand = c.loadXVecOperand
		loadDst = func() (string, error) { return c.loadX(dstArg.Reg) }
		storeDst = func(value string) error { return c.storeX(dstArg.Reg, value) }
	case vectorForm && isAMD64YReg(dstArg.Reg):
		byteWidth = 32
		loadOperand = c.loadYVecOperand
		loadDst = func() (string, error) { return c.loadY(dstArg.Reg) }
		storeDst = func(value string) error { return c.storeY(dstArg.Reg, value) }
	case vectorForm && isAMD64ZReg(dstArg.Reg):
		byteWidth = 64
		loadOperand = c.loadZVecOperand
		loadDst = func() (string, error) { return c.loadZ(dstArg.Reg) }
		storeDst = func(value string) error { return c.storeZ(dstArg.Reg, value) }
	default:
		return true, false, fmt.Errorf("amd64 %s has mismatched or non-vector destination: %q", baseOp, ins.Raw)
	}
	lanes := byteWidth / 4

	loadI32Lanes := func(arg Operand, allowBroadcast bool) (string, error) {
		if allowBroadcast && broadcast {
			value, err := c.evalIntSized(arg, I32)
			if err != nil {
				return "", err
			}
			return amd64SplatInteger(c, lanes, 32, value), nil
		}
		bytesValue, err := loadOperand(arg)
		if err != nil {
			return "", err
		}
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i32>\n", cast, byteWidth, bytesValue, lanes)
		return "%" + cast, nil
	}

	lhs, err := loadI32Lanes(ins.Args[0], true)
	if err != nil {
		return true, false, err
	}
	var rhs string
	if vectorForm {
		rhs, err = loadI32Lanes(ins.Args[1], false)
	} else {
		dstBytes, loadErr := loadDst()
		if loadErr != nil {
			return true, false, loadErr
		}
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", cast, dstBytes)
		rhs = "%" + cast
	}
	if err != nil {
		return true, false, err
	}
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul <%d x i32> %s, %s\n", product, lanes, lhs, rhs)
	result := "%" + product

	if masked {
		maskArg := ins.Args[2]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 VPMULLD masked form expects K1-K7: %q", ins.Raw)
		}
		maskIndex, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 VPMULLD masked form expects K1-K7: %q", ins.Raw)
		}
		mask, err := c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := loadDst()
		if err != nil {
			return true, false, err
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i32>\n", old, byteWidth, oldBytes, lanes)
		result = amd64ApplyI32LaneMask(c, lanes, result, "%"+old, mask, zeroMasking)
	}

	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i8>\n", out, lanes, result, byteWidth)
	return true, false, storeDst("%" + out)
}

func isAMD64MemoryOperand(op Operand) bool {
	switch op.Kind {
	case OpFP, OpMem, OpSym:
		return true
	default:
		return false
	}
}
