package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedArithmeticRightShift implements the two Go 1.27 packed uniform
// arithmetic-right-shift tables: legacy PSRAW/PSRAL use yps, VPSRAW/VPSRAD use
// _yvpslld, and EVEX-only VPSRAQ uses _yvpsraq.
func (c *amd64Ctx) lowerPackedArithmeticRightShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	switch baseOp {
	case "PSRAW":
		return c.lowerLegacyPackedArithmeticRightShift(baseOp, suffix, 16, ins)
	case "PSRAL":
		return c.lowerLegacyPackedArithmeticRightShift(baseOp, suffix, 32, ins)
	case "VPSRAW":
		return c.lowerVectorPackedArithmeticRightShift(baseOp, suffix, 16, false, ins)
	case "VPSRAD":
		return c.lowerVectorPackedArithmeticRightShift(baseOp, suffix, 32, true, ins)
	case "VPSRAQ":
		return c.lowerVectorPackedArithmeticRightShift(baseOp, suffix, 64, true, ins)
	default:
		return false, false, nil
	}
}

func (c *amd64Ctx) lowerLegacyPackedArithmeticRightShift(baseOp, suffix string, laneBits int, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects count, packed destination: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(destination); mmx {
		if ins.Args[0].Kind != OpImm && ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseMReg(ins.Args[0].Reg); !ok {
				return true, false, fmt.Errorf("%s %s MMX form requires an immediate, MMX, or memory count: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if ins.Args[0].Kind != OpImm && !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s MMX form requires an immediate, MMX, or memory count: %q", c.goarch, baseOp, ins.Raw)
		}
		dataBits, err := c.loadReg(destination)
		if err != nil {
			return true, false, err
		}
		lanes := 64 / laneBits
		data := c.bitcastI64ToIntegerLanes(lanes, laneBits, dataBits)
		count, err := c.loadPackedUniformShiftCount(ins.Args[0], true, laneBits)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedArithmeticRightShift(lanes, laneBits, data, count)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, lanes, laneBits, result)
		return true, false, c.storeReg(destination, "%"+bits)
	}

	if !c.isGoLegacyXReg(destination) {
		return true, false, fmt.Errorf("%s %s destination must be an in-range MMX or X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg && !c.isGoLegacyXReg(ins.Args[0].Reg) {
		return true, false, fmt.Errorf("%s %s XMM count must be an in-range X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm && ins.Args[0].Kind != OpReg && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s XMM form requires an immediate, X, or memory count: %q", c.goarch, baseOp, ins.Raw)
	}
	dataBytes, err := c.loadX(destination)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / laneBits
	data := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, dataBytes)
	count, err := c.loadPackedUniformShiftCount(ins.Args[0], false, laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedArithmeticRightShift(lanes, laneBits, data, count)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, laneBits, result)
	return true, false, c.storeX(destination, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedArithmeticRightShift(baseOp, suffix string, laneBits int, broadcastEnabled bool, ins Instr) (bool, bool, error) {
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.sae || properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s suffix is absent from its Go 1.27 table: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.broadcast && !broadcastEnabled {
		return true, false, fmt.Errorf("%s %s does not enable EVEX broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects count, source, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7 as its third operand: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}

	countArg, dataArg := ins.Args[0], ins.Args[1]
	immediate := countArg.Kind == OpImm
	if immediate {
		if countArg.Imm < -128 || countArg.Imm > 255 {
			return true, false, fmt.Errorf("%s %s immediate count is outside Go's signed/unsigned byte classes: %q", c.goarch, baseOp, ins.Raw)
		}
		if properties.broadcast {
			if !isAMD64MemoryOperand(dataArg) {
				return true, false, fmt.Errorf("%s %s.BCST requires an immediate count and scalar memory source: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if dataArg.Kind == OpReg {
			if !c.isGoPackedVectorMoveRegister(dataArg, byteWidth) {
				return true, false, fmt.Errorf("%s %s source register must match the destination width: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(dataArg) {
			return true, false, fmt.Errorf("%s %s immediate form requires matching vector or memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else {
		if properties.broadcast {
			return true, false, fmt.Errorf("%s %s.BCST is absent from variable-count rows: %q", c.goarch, baseOp, ins.Raw)
		}
		if countArg.Kind == OpReg {
			if !c.isGoPackedVectorMoveRegister(countArg, 16) {
				return true, false, fmt.Errorf("%s %s variable count must be X/m128: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(countArg) {
			return true, false, fmt.Errorf("%s %s variable count must be X/m128: %q", c.goarch, baseOp, ins.Raw)
		}
		if !c.isGoPackedVectorMoveRegister(dataArg, byteWidth) {
			return true, false, fmt.Errorf("%s %s variable-count data must be a matching vector register: %q", c.goarch, baseOp, ins.Raw)
		}
	}

	lanes := byteWidth * 8 / laneBits
	var data string
	var err error
	if properties.broadcast {
		var scalar string
		scalar, err = c.evalIntSized(dataArg, amd64IntegerTypeForBits(laneBits))
		if err == nil {
			data = amd64SplatInteger(c, lanes, laneBits, scalar)
		}
	} else {
		var bytesValue string
		bytesValue, err = c.loadPackedCompareBytes(dataArg, byteWidth)
		if err == nil {
			data = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, bytesValue)
		}
	}
	if err != nil {
		return true, false, err
	}
	count, err := c.loadPackedUniformShiftCount(countArg, false, laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedArithmeticRightShift(lanes, laneBits, data, count)
	if masked {
		mask, err := c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

// loadPackedUniformShiftCount returns an i64 count clamped to laneBits-1, as
// specified for x86 packed arithmetic shifts when the count is too large.
func (c *amd64Ctx) loadPackedUniformShiftCount(count Operand, mmx bool, laneBits int) (string, error) {
	if count.Kind == OpImm {
		value := uint64(count.Imm) & 0xff
		if value >= uint64(laneBits) {
			value = uint64(laneBits - 1)
		}
		return fmt.Sprintf("%d", value), nil
	}
	var count64 string
	var err error
	if mmx {
		count64, err = c.loadLegacyMMXPackedSource(count)
	} else {
		var countBytes string
		countBytes, err = c.loadXVecOperand(count)
		if err == nil {
			countWords := c.newTmp()
			low := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", countWords, countBytes)
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", low, countWords)
			count64 = "%" + low
		}
	}
	if err != nil {
		return "", err
	}
	inRange := c.newTmp()
	clamped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %d\n", inRange, count64, laneBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 %d\n", clamped, inRange, count64, laneBits-1)
	return "%" + clamped, nil
}

func (c *amd64Ctx) emitPackedArithmeticRightShift(lanes, laneBits int, data, count64 string) string {
	count := count64
	if laneBits < 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, count64, laneBits)
		count = "%" + narrow
	}
	counts := amd64SplatInteger(c, lanes, laneBits, count)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ashr <%d x i%d> %s, %s\n", result, lanes, laneBits, data, counts)
	return "%" + result
}
