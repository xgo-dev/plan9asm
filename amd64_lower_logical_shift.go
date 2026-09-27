package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedLogicalShiftSpec struct {
	laneBits int
	left     bool
	vector   bool
}

// amd64PackedLogicalShiftSpecs covers all Go 1.27 uniform packed logical
// shifts. Legacy operations use yps (MMX/XMM, immediate or packed count), and
// V-prefixed operations use _yvpslld (X/Y/Z data and an immediate or X/m128
// count, with the table's EVEX mask and D/Q broadcast forms).
var amd64PackedLogicalShiftSpecs = map[Op]amd64PackedLogicalShiftSpec{
	"PSLLW":  {laneBits: 16, left: true},
	"PSLLL":  {laneBits: 32, left: true},
	"PSLLQ":  {laneBits: 64, left: true},
	"PSRLW":  {laneBits: 16},
	"PSRLL":  {laneBits: 32},
	"PSRLQ":  {laneBits: 64},
	"VPSLLW": {laneBits: 16, left: true, vector: true},
	"VPSLLD": {laneBits: 32, left: true, vector: true},
	"VPSLLQ": {laneBits: 64, left: true, vector: true},
	"VPSRLW": {laneBits: 16, vector: true},
	"VPSRLD": {laneBits: 32, vector: true},
	"VPSRLQ": {laneBits: 64, vector: true},
}

func (c *amd64Ctx) lowerPackedLogicalShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64PackedLogicalShiftSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.vector {
		return c.lowerVectorPackedLogicalShift(baseOp, suffix, spec, ins)
	}
	return c.lowerLegacyPackedLogicalShift(baseOp, suffix, spec, ins)
}

func (c *amd64Ctx) lowerLegacyPackedLogicalShift(baseOp, suffix string, spec amd64PackedLogicalShiftSpec, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects count and packed destination: %q", c.goarch, baseOp, ins.Raw)
	}
	countArg, destination := ins.Args[0], ins.Args[1].Reg
	if countArg.Kind == OpImm && (countArg.Imm < -128 || countArg.Imm > 127) {
		return true, false, fmt.Errorf("%s %s immediate count is outside Go's Yi8 class: %q", c.goarch, baseOp, ins.Raw)
	}
	if _, mmx := amd64ParseMReg(destination); mmx {
		if countArg.Kind == OpReg {
			if _, ok := amd64ParseMReg(countArg.Reg); !ok {
				return true, false, fmt.Errorf("%s %s MMX form requires an immediate, MMX, or memory count: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if countArg.Kind != OpImm && !isAMD64MemoryOperand(countArg) {
			return true, false, fmt.Errorf("%s %s MMX form requires an immediate, MMX, or memory count: %q", c.goarch, baseOp, ins.Raw)
		}
		dataBits, err := c.loadReg(destination)
		if err != nil {
			return true, false, err
		}
		lanes := 64 / spec.laneBits
		data := c.bitcastI64ToIntegerLanes(lanes, spec.laneBits, dataBits)
		count, err := c.loadPackedUniformLogicalShiftCount(countArg, true)
		if err != nil {
			return true, false, err
		}
		result := c.emitPackedLogicalShift(spec, lanes, data, count)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", bits, lanes, spec.laneBits, result)
		return true, false, c.storeReg(destination, "%"+bits)
	}

	if !c.isGoLegacyXReg(destination) {
		return true, false, fmt.Errorf("%s %s destination must be an in-range MMX or X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if countArg.Kind == OpReg {
		if !c.isGoLegacyXReg(countArg.Reg) {
			return true, false, fmt.Errorf("%s %s XMM form requires an immediate, X, or memory count: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if countArg.Kind != OpImm && !isAMD64MemoryOperand(countArg) {
		return true, false, fmt.Errorf("%s %s XMM form requires an immediate, X, or memory count: %q", c.goarch, baseOp, ins.Raw)
	}
	dataBytes, err := c.loadX(destination)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / spec.laneBits
	data := c.bitcastVectorBytesToIntegerLanes(16, lanes, spec.laneBits, dataBytes)
	count, err := c.loadPackedUniformLogicalShiftCount(countArg, false)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedLogicalShift(spec, lanes, data, count)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, spec.laneBits, result)
	return true, false, c.storeX(destination, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedLogicalShift(baseOp, suffix string, spec amd64PackedLogicalShiftSpec, ins Instr) (bool, bool, error) {
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.sae || properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s suffix is absent from its Go 1.27 table: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.broadcast && spec.laneBits == 16 {
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

	lanes := byteWidth * 8 / spec.laneBits
	var data string
	if properties.broadcast {
		scalar, err := c.evalIntSized(dataArg, amd64IntegerTypeForBits(spec.laneBits))
		if err != nil {
			return true, false, err
		}
		data = amd64SplatInteger(c, lanes, spec.laneBits, scalar)
	} else {
		bytesValue, err := c.loadPackedCompareBytes(dataArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		data = c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, bytesValue)
	}
	count, err := c.loadPackedUniformLogicalShiftCount(countArg, false)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedLogicalShift(spec, lanes, data, count)
	if masked {
		mask, err := c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) loadPackedUniformLogicalShiftCount(count Operand, mmx bool) (string, error) {
	if count.Kind == OpImm {
		return fmt.Sprintf("%d", uint8(count.Imm)), nil
	}
	if mmx {
		return c.loadLegacyMMXPackedSource(count)
	}
	countBytes, err := c.loadXVecOperand(count)
	if err != nil {
		return "", err
	}
	countWords := c.newTmp()
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", countWords, countBytes)
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", low, countWords)
	return "%" + low, nil
}

func (c *amd64Ctx) emitPackedLogicalShift(spec amd64PackedLogicalShiftSpec, lanes int, data, count64 string) string {
	inRange := c.newTmp()
	safe64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %d\n", inRange, count64, spec.laneBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 0\n", safe64, inRange, count64)
	count := "%" + safe64
	if spec.laneBits < 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, count, spec.laneBits)
		count = "%" + narrow
	}
	counts := amd64SplatInteger(c, lanes, spec.laneBits, count)
	shifted := c.newTmp()
	operation := "lshr"
	if spec.left {
		operation = "shl"
	}
	typeName := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shifted, operation, typeName, data, counts)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s zeroinitializer\n", result, inRange, typeName, shifted, typeName)
	return "%" + result
}
