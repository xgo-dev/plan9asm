package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedUnpack implements the complete Go 1.27 packed interleave family:
// integer and floating legacy forms plus their VEX/EVEX X/Y/Z counterparts.
// The unusual legacy LWL/HWL and LLQ/HLQ spellings are Go assembler names.
func (c *amd64Ctx) lowerPackedUnpack(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, high, vector, legacyMMX, broadcast, recognized := amd64PackedUnpackProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if !vector {
		return c.lowerLegacyPackedUnpack(baseOp, suffix, laneBits, high, legacyMMX, ins)
	}
	return c.lowerVectorPackedUnpack(baseOp, suffix, laneBits, high, broadcast, ins)
}

func amd64PackedUnpackProperties(op string) (laneBits int, high, vector, legacyMMX, broadcast, ok bool) {
	switch op {
	case "PUNPCKLBW":
		return 8, false, false, true, false, true
	case "PUNPCKHBW":
		return 8, true, false, true, false, true
	case "PUNPCKLWL":
		return 16, false, false, true, false, true
	case "PUNPCKHWL":
		return 16, true, false, true, false, true
	case "PUNPCKLLQ":
		return 32, false, false, true, false, true
	case "PUNPCKHLQ":
		return 32, true, false, true, false, true
	case "PUNPCKLQDQ":
		return 64, false, false, false, false, true
	case "PUNPCKHQDQ":
		return 64, true, false, false, false, true
	case "UNPCKLPS":
		return 32, false, false, false, false, true
	case "UNPCKHPS":
		return 32, true, false, false, false, true
	case "UNPCKLPD":
		return 64, false, false, false, false, true
	case "UNPCKHPD":
		return 64, true, false, false, false, true
	case "VPUNPCKLBW":
		return 8, false, true, false, false, true
	case "VPUNPCKHBW":
		return 8, true, true, false, false, true
	case "VPUNPCKLWD":
		return 16, false, true, false, false, true
	case "VPUNPCKHWD":
		return 16, true, true, false, false, true
	case "VPUNPCKLDQ":
		return 32, false, true, false, true, true
	case "VPUNPCKHDQ":
		return 32, true, true, false, true, true
	case "VPUNPCKLQDQ":
		return 64, false, true, false, true, true
	case "VPUNPCKHQDQ":
		return 64, true, true, false, true, true
	case "VUNPCKLPS":
		return 32, false, true, false, true, true
	case "VUNPCKHPS":
		return 32, true, true, false, true, true
	case "VUNPCKLPD":
		return 64, false, true, false, true, true
	case "VUNPCKHPD":
		return 64, true, true, false, true, true
	default:
		return 0, false, false, false, false, false
	}
}

func (c *amd64Ctx) lowerLegacyPackedUnpack(baseOp, suffix string, laneBits int, high, legacyMMX bool, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects packed source, packed destination: %q", c.goarch, baseOp, ins.Raw)
	}
	dst := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(dst); mmx {
		if !legacyMMX {
			return true, false, fmt.Errorf("%s %s has no MMX row in Go 1.27's yxm table: %q", c.goarch, baseOp, ins.Raw)
		}
		if c.goarch != "amd64" {
			return true, false, fmt.Errorf("386 %s MMX form is illegal in 32-bit mode: %q", baseOp, ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, fmt.Errorf("amd64 %s MMX source: %w", baseOp, err)
		}
		secondBits, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		lanes := 64 / laneBits
		first := c.bitcastI64ToIntegerLanes(lanes, laneBits, firstBits)
		second := c.bitcastI64ToIntegerLanes(lanes, laneBits, secondBits)
		result := c.emitPackedUnpackLanes(8, laneBits, high, first, second)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, lanes, laneBits, result)
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
	lanes := 128 / laneBits
	first := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, firstBytes)
	second := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, secondBytes)
	result := c.emitPackedUnpackLanes(16, laneBits, high, first, second)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, laneBits, result)
	return true, false, c.storeX(dst, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedUnpack(baseOp, suffix string, laneBits int, high, supportsBroadcast bool, ins Instr) (bool, bool, error) {
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
	if broadcast && !supportsBroadcast {
		return true, false, fmt.Errorf("%s %s has no broadcast encoding in Go 1.27's optab: %q", c.goarch, baseOp, ins.Raw)
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
	if !amd64EVEXVectorRegister(dstArg, byteWidth) || !amd64EVEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source and destination must be same-width vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && byteWidth == 64 {
		for _, arg := range []Operand{ins.Args[1], dstArg} {
			index, _ := amd64VectorRegisterIndex(arg.Reg, byteWidth)
			if index >= 8 {
				return true, false, fmt.Errorf("386 %s Z register is outside Go 1.27's 32-bit EVEX range: %q", baseOp, ins.Raw)
			}
		}
	}
	if broadcast {
		if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory first source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if ins.Args[0].Kind == OpReg {
		if !amd64EVEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match its destination width: %q", c.goarch, baseOp, ins.Raw)
		}
		if c.goarch == "386" && byteWidth == 64 {
			index, _ := amd64VectorRegisterIndex(ins.Args[0].Reg, byteWidth)
			if index >= 8 {
				return true, false, fmt.Errorf("386 %s Z register is outside Go 1.27's 32-bit EVEX range: %q", baseOp, ins.Raw)
			}
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
	lanes := byteWidth * 8 / laneBits
	var first string
	var err error
	if broadcast {
		var scalar string
		scalar, err = c.evalIntSized(ins.Args[0], amd64IntegerTypeForBits(laneBits))
		if err == nil {
			first = amd64SplatInteger(c, lanes, laneBits, scalar)
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
	result := c.emitPackedUnpackLanes(byteWidth, laneBits, high, first, second)
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

// emitPackedUnpackLanes interleaves the second (vvvv/old destination) source
// with the first (r/m) source independently within each 128-bit vector lane.
func (c *amd64Ctx) emitPackedUnpackLanes(byteWidth, laneBits int, high bool, first, second string) string {
	lanes := byteWidth * 8 / laneBits
	groupBits := 128
	if byteWidth == 8 {
		groupBits = 64
	}
	groupLanes := groupBits / laneBits
	half := groupLanes / 2
	start := 0
	if high {
		start = half
	}
	mask := make([]string, 0, lanes)
	for group := 0; group < lanes/groupLanes; group++ {
		base := group * groupLanes
		for lane := start; lane < start+half; lane++ {
			index := base + lane
			mask = append(mask, fmt.Sprintf("i32 %d", index), fmt.Sprintf("i32 %d", lanes+index))
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> %s, <%d x i32> <%s>\n",
		result, lanes, laneBits, second, lanes, laneBits, first, lanes, strings.Join(mask, ", "))
	return "%" + result
}
