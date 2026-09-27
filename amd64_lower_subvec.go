package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedSubtractMode uint8

const (
	amd64PackedSubtractWrap amd64PackedSubtractMode = iota
	amd64PackedSubtractSignedSaturating
	amd64PackedSubtractUnsignedSaturating
)

// lowerPackedIntegerSubtract implements the complete Go 1.27 packed-integer
// subtract family: legacy yxm XMM forms and the shared _yvandnpd VEX/EVEX
// forms, including the 386 frontend's narrower EVEX surface.
func (c *amd64Ctx) lowerPackedIntegerSubtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, mode, vector, recognized := amd64PackedSubtractProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if !vector {
		if suffix != "" {
			return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
		}
		return c.lowerLegacyPackedIntegerSubtract(baseOp, laneBits, mode, ins)
	}
	return c.lowerVectorPackedIntegerSubtract(baseOp, suffix, laneBits, mode, ins)
}

func amd64PackedSubtractProperties(op string) (laneBits int, mode amd64PackedSubtractMode, vector, ok bool) {
	switch op {
	case "PSUBB":
		return 8, amd64PackedSubtractWrap, false, true
	case "PSUBW":
		return 16, amd64PackedSubtractWrap, false, true
	case "PSUBL":
		return 32, amd64PackedSubtractWrap, false, true
	case "PSUBQ":
		return 64, amd64PackedSubtractWrap, false, true
	case "PSUBSB":
		return 8, amd64PackedSubtractSignedSaturating, false, true
	case "PSUBSW":
		return 16, amd64PackedSubtractSignedSaturating, false, true
	case "PSUBUSB":
		return 8, amd64PackedSubtractUnsignedSaturating, false, true
	case "PSUBUSW":
		return 16, amd64PackedSubtractUnsignedSaturating, false, true
	case "VPSUBB":
		return 8, amd64PackedSubtractWrap, true, true
	case "VPSUBW":
		return 16, amd64PackedSubtractWrap, true, true
	case "VPSUBD":
		return 32, amd64PackedSubtractWrap, true, true
	case "VPSUBQ":
		return 64, amd64PackedSubtractWrap, true, true
	case "VPSUBSB":
		return 8, amd64PackedSubtractSignedSaturating, true, true
	case "VPSUBSW":
		return 16, amd64PackedSubtractSignedSaturating, true, true
	case "VPSUBUSB":
		return 8, amd64PackedSubtractUnsignedSaturating, true, true
	case "VPSUBUSW":
		return 16, amd64PackedSubtractUnsignedSaturating, true, true
	default:
		return 0, 0, false, false
	}
}

func (c *amd64Ctx) lowerLegacyPackedIntegerSubtract(baseOp string, laneBits int, mode amd64PackedSubtractMode, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("%s %s expects X/m128, X: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s %s register source is outside the legacy X class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[0], 16)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, secondBytes)
	result := c.emitPackedIntegerSubtract(lanes, laneBits, first, second, mode)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, laneBits, result)
	return true, false, c.storeX(ins.Args[1].Reg, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedIntegerSubtract(baseOp, suffix string, laneBits int, mode amd64PackedSubtractMode, ins Instr) (bool, bool, error) {
	broadcast, zeroing := false, false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	case "BCST":
		broadcast = true
	case "BCST.Z":
		broadcast, zeroing = true, true
	default:
		return true, false, fmt.Errorf("%s %s has a suffix absent from its Go 1.27 optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if broadcast && baseOp != "VPSUBD" && baseOp != "VPSUBQ" {
		return true, false, fmt.Errorf("%s %s does not enable EVEX broadcast: %q", c.goarch, baseOp, ins.Raw)
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
	if broadcast {
		if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory first source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if ins.Args[0].Kind == OpReg {
		if !amd64EVEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match its destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	var mask string
	if masked {
		maskArg := ins.Args[2]
		if !amd64NonzeroKOperand(maskArg) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		var err error
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / laneBits
	var first string
	var err error
	if broadcast {
		first, err = c.evalIntSized(ins.Args[0], amd64IntegerTypeForBits(laneBits))
		if err == nil {
			first = amd64SplatInteger(c, lanes, laneBits, first)
		}
	} else {
		var firstBytes string
		firstBytes, err = c.loadPackedCompareBytes(ins.Args[0], byteWidth)
		if err == nil {
			first = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, firstBytes)
		}
	}
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, secondBytes)
	result := c.emitPackedIntegerSubtract(lanes, laneBits, first, second, mode)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, "%"+out)
}

// emitPackedIntegerSubtract computes second-first, matching Go assembler's
// rm,v,destination operand order.
func (c *amd64Ctx) emitPackedIntegerSubtract(lanes, laneBits int, first, second string, mode amd64PackedSubtractMode) string {
	vecType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	if mode == amd64PackedSubtractWrap {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", result, vecType, second, first)
		return "%" + result
	}

	wideBits := laneBits * 2
	wideType := fmt.Sprintf("<%d x i%d>", lanes, wideBits)
	extend := "sext"
	if mode == amd64PackedSubtractUnsignedSaturating {
		extend = "zext"
	}
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", firstWide, extend, vecType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", secondWide, extend, vecType, second, wideType)
	difference := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", difference, wideType, secondWide, firstWide)

	clamped := "%" + difference
	minValue := int64(0)
	if mode == amd64PackedSubtractSignedSaturating {
		minValue = -int64(uint64(1) << (laneBits - 1))
	}
	below := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, %s\n", below, wideType, clamped, llvmSplatSignedInteger(lanes, wideBits, minValue))
	boundedBelow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", boundedBelow, lanes, below, wideType, llvmSplatSignedInteger(lanes, wideBits, minValue), wideType, clamped)
	clamped = "%" + boundedBelow
	if mode == amd64PackedSubtractSignedSaturating {
		maxValue := int64((uint64(1) << (laneBits - 1)) - 1)
		above := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp sgt %s %s, %s\n", above, wideType, clamped, llvmSplatSignedInteger(lanes, wideBits, maxValue))
		boundedAbove := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", boundedAbove, lanes, above, wideType, llvmSplatSignedInteger(lanes, wideBits, maxValue), wideType, clamped)
		clamped = "%" + boundedAbove
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", result, wideType, clamped, vecType)
	return "%" + result
}
