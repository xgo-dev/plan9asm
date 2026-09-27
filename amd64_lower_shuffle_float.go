package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedFloatShuffle implements the complete Go 1.27 SHUFPS/SHUFPD
// and VSHUFPS/VSHUFPD operand tables, using integer lanes to preserve bits.
func (c *amd64Ctx) lowerPackedFloatShuffle(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, vector, recognized := amd64PackedFloatShuffleProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if !vector {
		return c.lowerLegacyPackedFloatShuffle(baseOp, suffix, laneBits, ins)
	}
	return c.lowerVectorPackedFloatShuffle(baseOp, suffix, laneBits, ins)
}

func amd64PackedFloatShuffleProperties(op string) (laneBits int, vector, ok bool) {
	switch op {
	case "SHUFPS":
		return 32, false, true
	case "SHUFPD":
		return 64, false, true
	case "VSHUFPS":
		return 32, true, true
	case "VSHUFPD":
		return 64, true, true
	default:
		return 0, false, false
	}
}

func amd64UnsignedImm8(arg Operand) (uint8, bool) {
	if arg.Kind != OpImm || arg.Imm < 0 || arg.Imm > 255 {
		return 0, false
	}
	return uint8(arg.Imm), true
}

func (c *amd64Ctx) lowerLegacyPackedFloatShuffle(baseOp, suffix string, laneBits int, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects $u8, X/m128, X: %q", c.goarch, baseOp, ins.Raw)
	}
	imm, ok := amd64UnsignedImm8(ins.Args[0])
	if !ok {
		return true, false, fmt.Errorf("%s %s immediate is outside Go 1.27's unsigned-imm8 class: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[2].Kind != OpReg || !c.isGoLegacyXReg(ins.Args[2].Reg) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[1].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's legacy X class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	firstBytes, err := c.loadPackedCompareBytes(ins.Args[1], 16)
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadX(ins.Args[2].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, secondBytes)
	result := c.emitPackedFloatShuffle(laneBits, 16, imm, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, laneBits, result)
	return true, false, c.storeX(ins.Args[2].Reg, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedFloatShuffle(baseOp, suffix string, laneBits int, ins Instr) (bool, bool, error) {
	if c.goarch != "amd64" {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
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
		return true, false, fmt.Errorf("amd64 %s has a suffix absent from its Go 1.27 optab: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("amd64 %s expects $u8, src1, src2, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	imm, ok := amd64UnsignedImm8(ins.Args[0])
	if !ok {
		return true, false, fmt.Errorf("amd64 %s immediate is outside Go 1.27's unsigned-imm8 class: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 5
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects a vector-register destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("amd64 %s expects an X, Y, or Z destination: %q", baseOp, ins.Raw)
	}
	if !amd64EVEXVectorRegister(dstArg, byteWidth) || !amd64EVEXVectorRegister(ins.Args[2], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source and destination must be same-width vector registers: %q", baseOp, ins.Raw)
	}
	if broadcast {
		if !isAMD64MemoryOperand(ins.Args[1]) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
		}
	} else if ins.Args[1].Kind == OpReg {
		if !amd64EVEXVectorRegister(ins.Args[1], byteWidth) {
			return true, false, fmt.Errorf("amd64 %s first source must match its destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s first source must be a vector register or memory: %q", baseOp, ins.Raw)
	}

	var mask string
	if masked {
		if !amd64NonzeroKOperand(ins.Args[3]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		var err error
		mask, err = c.loadK(ins.Args[3].Reg)
		if err != nil {
			return true, false, err
		}
	}
	lanes := byteWidth * 8 / laneBits
	var first string
	var err error
	if broadcast {
		first, err = c.evalIntSized(ins.Args[1], amd64IntegerTypeForBits(laneBits))
		if err == nil {
			first = amd64SplatInteger(c, lanes, laneBits, first)
		}
	} else {
		var firstBytes string
		firstBytes, err = c.loadPackedCompareBytes(ins.Args[1], byteWidth)
		if err == nil {
			first = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, firstBytes)
		}
	}
	if err != nil {
		return true, false, err
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[2], byteWidth)
	if err != nil {
		return true, false, err
	}
	second := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, secondBytes)
	result := c.emitPackedFloatShuffle(laneBits, byteWidth, imm, first, second)
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

func (c *amd64Ctx) emitPackedFloatShuffle(laneBits, byteWidth int, imm uint8, first, second string) string {
	lanes := byteWidth * 8 / laneBits
	groupLanes := 128 / laneBits
	vecType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		groupBase := lane / groupLanes * groupLanes
		position := lane % groupLanes
		source := second
		selector := 0
		if laneBits == 32 {
			selector = int(imm>>(2*position)) & 3
			if position >= 2 {
				source = first
			}
		} else {
			selector = int(imm>>lane) & 1
			if position == 1 {
				source = first
			}
		}
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", extracted, vecType, source, groupBase+selector)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, vecType, result, laneBits, extracted, lane)
		result = "%" + inserted
	}
	return result
}
