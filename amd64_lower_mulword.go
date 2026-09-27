package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedWordMultiplyMode uint8

const (
	amd64PackedWordMultiplyLow amd64PackedWordMultiplyMode = iota
	amd64PackedWordMultiplySignedHigh
	amd64PackedWordMultiplyUnsignedHigh
	amd64PackedWordMultiplyRoundedSignedHigh
)

// lowerPackedWordMultiply implements every Go 1.27 form of PMULLW,
// PMULHW, PMULHUW, PMULHRSW and their VEX/EVEX counterparts.
func (c *amd64Ctx) lowerPackedWordMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	mode, vector, recognized := amd64PackedWordMultiplyProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if !vector {
		return c.lowerLegacyPackedWordMultiply(baseOp, suffix, mode, ins)
	}
	return c.lowerVectorPackedWordMultiply(baseOp, suffix, mode, ins)
}

func amd64PackedWordMultiplyProperties(op string) (mode amd64PackedWordMultiplyMode, vector, ok bool) {
	switch op {
	case "PMULLW":
		return amd64PackedWordMultiplyLow, false, true
	case "PMULHW":
		return amd64PackedWordMultiplySignedHigh, false, true
	case "PMULHUW":
		return amd64PackedWordMultiplyUnsignedHigh, false, true
	case "PMULHRSW":
		return amd64PackedWordMultiplyRoundedSignedHigh, false, true
	case "VPMULLW":
		return amd64PackedWordMultiplyLow, true, true
	case "VPMULHW":
		return amd64PackedWordMultiplySignedHigh, true, true
	case "VPMULHUW":
		return amd64PackedWordMultiplyUnsignedHigh, true, true
	case "VPMULHRSW":
		return amd64PackedWordMultiplyRoundedSignedHigh, true, true
	default:
		return 0, false, false
	}
}

func (c *amd64Ctx) lowerLegacyPackedWordMultiply(baseOp, suffix string, mode amd64PackedWordMultiplyMode, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects packed source, packed destination: %q", c.goarch, baseOp, ins.Raw)
	}
	dst := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(dst); mmx {
		if c.goarch != "amd64" {
			return true, false, fmt.Errorf("386 %s MMX form is illegal in 32-bit mode: %q", baseOp, ins.Raw)
		}
		if mode == amd64PackedWordMultiplyRoundedSignedHigh {
			return true, false, fmt.Errorf("amd64 PMULHRSW has no MMX row in Go 1.27's yxm_q4 table: %q", ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, fmt.Errorf("amd64 %s MMX source: %w", baseOp, err)
		}
		secondBits, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		first := c.bitcastI64ToIntegerLanes(4, 16, firstBits)
		second := c.bitcastI64ToIntegerLanes(4, 16, secondBits)
		result := c.emitPackedWordMultiply(4, first, second, mode)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i16> %s to i64\n", bits, result)
		return true, false, c.storeReg(dst, "%"+bits)
	}

	if !c.isGoLegacyXReg(dst) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s %s XMM source is outside Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[0], 16)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(dst)
	if err != nil {
		return true, false, err
	}
	first := c.bitcastVectorBytesToIntegerLanes(16, 8, 16, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, 8, 16, secondBytes)
	result := c.emitPackedWordMultiply(8, first, second, mode)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %s to <16 x i8>\n", out, result)
	return true, false, c.storeX(dst, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedWordMultiply(baseOp, suffix string, mode amd64PackedWordMultiplyMode, ins Instr) (bool, bool, error) {
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s %s has a suffix absent from its Go 1.27 optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects src1, src2, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects a vector-register destination: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s expects an X, Y, or Z destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && byteWidth == 64 {
		return true, false, fmt.Errorf("386 %s has no Z-width form in Go 1.27's assembler frontend: %q", baseOp, ins.Raw)
	}
	if !amd64EVEXVectorRegister(dstArg, byteWidth) || !amd64EVEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source and destination must be same-width vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !amd64EVEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match its destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	var mask string
	if masked {
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		var err error
		mask, err = c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[0], byteWidth)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth / 2
	first := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 16, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 16, secondBytes)
	result := c.emitPackedWordMultiply(lanes, first, second, mode)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, 16, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, 16, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x i8>\n", out, lanes, result, byteWidth)
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedWordMultiply(lanes int, first, second string, mode amd64PackedWordMultiplyMode) string {
	wordType := fmt.Sprintf("<%d x i16>", lanes)
	if mode == amd64PackedWordMultiplyLow {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", result, wordType, second, first)
		return "%" + result
	}

	wideType := fmt.Sprintf("<%d x i32>", lanes)
	extend := "sext"
	shift := int64(16)
	if mode == amd64PackedWordMultiplyUnsignedHigh {
		extend = "zext"
	}
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", firstWide, extend, wordType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", secondWide, extend, wordType, second, wideType)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", product, wideType, secondWide, firstWide)
	value := "%" + product
	if mode == amd64PackedWordMultiplyRoundedSignedHigh {
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", rounded, wideType, value, llvmSplatSignedInteger(lanes, 32, 16384))
		value = "%" + rounded
		shift = 15
	}
	shifted := c.newTmp()
	shiftOp := "ashr"
	if mode == amd64PackedWordMultiplyUnsignedHigh {
		shiftOp = "lshr"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shifted, shiftOp, wideType, value, llvmSplatSignedInteger(lanes, 32, shift))
	value = "%" + shifted
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", result, wideType, value, wordType)
	return "%" + result
}
