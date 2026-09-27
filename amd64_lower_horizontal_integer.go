package plan9asm

import (
	"fmt"
	"strings"
)

type amd64HorizontalIntegerSpec struct {
	laneBits int
	subtract bool
	saturate bool
	vector   bool
	allowMMX bool
	// VEX.66.0F38 opcode, shared by raw decoding and typed lowering.
	opcode byte
}

// amd64HorizontalIntegerSpecs covers the complete Go 1.27 PHADD/PHSUB
// family. PHADDD's legacy ymmxmm0f38 table uniquely includes MMX; the other
// legacy operations use yxm_q4. All V-prefixed operations use _yvaddsubpd,
// which has only VEX X/Y rows.
var amd64HorizontalIntegerSpecs = map[Op]amd64HorizontalIntegerSpec{
	"PHADDD":   {laneBits: 32, allowMMX: true},
	"PHADDSW":  {laneBits: 16, saturate: true},
	"PHADDW":   {laneBits: 16},
	"PHSUBD":   {laneBits: 32, subtract: true},
	"PHSUBSW":  {laneBits: 16, subtract: true, saturate: true},
	"PHSUBW":   {laneBits: 16, subtract: true},
	"VPHADDD":  {laneBits: 32, vector: true, opcode: 0x02},
	"VPHADDSW": {laneBits: 16, saturate: true, vector: true, opcode: 0x03},
	"VPHADDW":  {laneBits: 16, vector: true, opcode: 0x01},
	"VPHSUBD":  {laneBits: 32, subtract: true, vector: true, opcode: 0x06},
	"VPHSUBSW": {laneBits: 16, subtract: true, saturate: true, vector: true, opcode: 0x07},
	"VPHSUBW":  {laneBits: 16, subtract: true, vector: true, opcode: 0x05},
}

func (c *amd64Ctx) lowerHorizontalInteger(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64HorizontalIntegerSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed forms in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.vector {
		return c.lowerVectorHorizontalInteger(baseOp, spec, ins)
	}
	return c.lowerLegacyHorizontalInteger(baseOp, spec, ins)
}

func (c *amd64Ctx) lowerLegacyHorizontalInteger(baseOp string, spec amd64HorizontalIntegerSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects packed source and destination: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[1].Reg
	if _, mmx := amd64ParseMReg(destination); mmx {
		if !spec.allowMMX {
			return true, false, fmt.Errorf("%s %s has no MMX form in Go 1.27's yxm_q4 table: %q", c.goarch, baseOp, ins.Raw)
		}
		if ins.Args[0].Kind == OpReg {
			if _, ok := amd64ParseMReg(ins.Args[0].Reg); !ok {
				return true, false, fmt.Errorf("%s %s MMX form requires an MMX source: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s MMX form requires MMX or memory source: %q", c.goarch, baseOp, ins.Raw)
		}
		firstBits, err := c.loadLegacyMMXPackedSource(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		secondBits, err := c.loadReg(destination)
		if err != nil {
			return true, false, err
		}
		first := c.bitcastI64ToIntegerLanes(2, 32, firstBits)
		second := c.bitcastI64ToIntegerLanes(2, 32, secondBits)
		result := c.emitHorizontalInteger(spec, 8, first, second)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i32> %s to i64\n", bits, result)
		return true, false, c.storeReg(destination, "%"+bits)
	}

	if !c.isGoLegacyXReg(destination) {
		return true, false, fmt.Errorf("%s %s destination must be an in-range X register: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg {
		if !c.isGoLegacyXReg(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s %s source must be an in-range X register or memory: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s source must be an in-range X register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	first, err := c.loadHorizontalIntegerOperand(ins.Args[0], 16, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalIntegerOperand(ins.Args[1], 16, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitHorizontalInteger(spec, 16, first, second)
	lanes := 128 / spec.laneBits
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, lanes, spec.laneBits, result)
	return true, false, c.storeX(destination, "%"+out)
}

func (c *amd64Ctx) lowerVectorHorizontalInteger(baseOp string, spec amd64HorizontalIntegerSpec, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects source2, source1, destination: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(ins.Args[2].Reg)
	// Go's VEX frontend accepts X/Y0-15 in both modes. This differs from
	// legacy SSE and from the raw decoder's physical 32-bit register limit.
	if byteWidth != 16 && byteWidth != 32 ||
		!amd64VEXVectorRegister(ins.Args[2], byteWidth) ||
		!amd64VEXVectorRegister(ins.Args[1], byteWidth) ||
		!(amd64VEXVectorRegister(ins.Args[0], byteWidth) || isAMD64MemoryOperand(ins.Args[0])) {
		return true, false, fmt.Errorf("%s %s requires matching in-range VEX X/Y sources and destination: %q", c.goarch, baseOp, ins.Raw)
	}
	first, err := c.loadHorizontalIntegerOperand(ins.Args[0], byteWidth, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadHorizontalIntegerOperand(ins.Args[1], byteWidth, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	result := c.emitHorizontalInteger(spec, byteWidth, first, second)
	lanes := byteWidth * 8 / spec.laneBits
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(ins.Args[2], byteWidth, "%"+out)
}

func (c *amd64Ctx) loadHorizontalIntegerOperand(operand Operand, byteWidth, laneBits int) (string, error) {
	bytesValue, err := c.loadPackedCompareBytes(operand, byteWidth)
	if err != nil {
		return "", err
	}
	lanes := byteWidth * 8 / laneBits
	return c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, bytesValue), nil
}

func (c *amd64Ctx) emitHorizontalInteger(spec amd64HorizontalIntegerSpec, byteWidth int, first, second string) string {
	lanes := byteWidth * 8 / spec.laneBits
	lanesPer128 := 128 / spec.laneBits
	// The legacy MMX PHADDD row is one 64-bit lane group rather than one
	// 128-bit group, but the same half-from-each-source construction applies.
	if byteWidth == 8 {
		lanesPer128 = lanes
	}
	typeName := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	elementType := fmt.Sprintf("i%d", spec.laneBits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		position := lane % lanesPer128
		block := lane - position
		source := second
		pair := position
		if position >= lanesPer128/2 {
			source = first
			pair -= lanesPer128 / 2
		}
		leftIndex := block + 2*pair
		rightIndex := leftIndex + 1
		left := c.newTmp()
		right := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", left, typeName, source, leftIndex)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", right, typeName, source, rightIndex)
		value := c.emitHorizontalIntegerPair(spec, "%"+left, "%"+right)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n", inserted, typeName, result, elementType, value, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitHorizontalIntegerPair(spec amd64HorizontalIntegerSpec, left, right string) string {
	operation := "add"
	if spec.subtract {
		operation = "sub"
	}
	if !spec.saturate {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i%d %s, %s\n", value, operation, spec.laneBits, left, right)
		return "%" + value
	}
	leftWide := c.newTmp()
	rightWide := c.newTmp()
	value := c.newTmp()
	below := c.newTmp()
	lowerClamped := c.newTmp()
	above := c.newTmp()
	clamped := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", leftWide, left)
	fmt.Fprintf(c.b, "  %%%s = sext i16 %s to i32\n", rightWide, right)
	fmt.Fprintf(c.b, "  %%%s = %s i32 %%%s, %%%s\n", value, operation, leftWide, rightWide)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, -32768\n", below, value)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 -32768, i32 %%%s\n", lowerClamped, below, value)
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i32 %%%s, 32767\n", above, lowerClamped)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 32767, i32 %%%s\n", clamped, above, lowerClamped)
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to i16\n", result, clamped)
	return "%" + result
}
