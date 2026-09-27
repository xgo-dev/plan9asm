package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PerLaneVariableShiftSpec struct {
	laneBits   int
	operation  string
	arithmetic bool
	// Shared raw grammar: 66.0F38 opcode and optional VEX generation.
	// W is fixed: W0 for dwords, W1 for words/qwords.
	opcode byte
	vex    bool
}

var amd64PerLaneVariableShiftSpecs = map[string]amd64PerLaneVariableShiftSpec{
	"VPSLLVW": {laneBits: 16, operation: "shl", opcode: 0x12},
	"VPSLLVD": {laneBits: 32, operation: "shl", opcode: 0x47, vex: true},
	"VPSLLVQ": {laneBits: 64, operation: "shl", opcode: 0x47, vex: true},
	"VPSRLVW": {laneBits: 16, operation: "lshr", opcode: 0x10},
	"VPSRLVD": {laneBits: 32, operation: "lshr", opcode: 0x45, vex: true},
	"VPSRLVQ": {laneBits: 64, operation: "lshr", opcode: 0x45, vex: true},
	"VPSRAVW": {laneBits: 16, operation: "ashr", arithmetic: true, opcode: 0x11},
	"VPSRAVD": {laneBits: 32, operation: "ashr", arithmetic: true, opcode: 0x46, vex: true},
	"VPSRAVQ": {laneBits: 64, operation: "ashr", arithmetic: true, opcode: 0x46},
}

// lowerPerLaneVariableShift implements the full Go 1.27 per-lane packed
// variable-shift family. The first Plan 9 source supplies one count per lane.
func (c *amd64Ctx) lowerPerLaneVariableShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, ok := amd64PerLaneVariableShiftSpecs[baseOp]
	if !ok {
		return false, false, nil
	}
	suffixes, err := amd64ParseTwoSourcePermuteSuffixes(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	if suffixes.broadcast && spec.laneBits == 16 {
		return true, false, fmt.Errorf("amd64 %s does not enable broadcast in Go 1.27: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects per-lane counts, source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if masked && c.goarch == "386" && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s masked form exceeds the Go assembler frontend's operand limit: %q", baseOp, ins.Raw)
	}
	if suffixes.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	byteWidth := 0
	if destination.Kind == OpReg {
		byteWidth = amd64VectorByteWidth(destination.Reg)
	}
	if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s expects an in-range X, Y, or Z destination: %q", baseOp, ins.Raw)
	}
	data := ins.Args[1]
	if !c.isGoPackedVectorMoveRegister(data, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s data source must match the destination width: %q", baseOp, ins.Raw)
	}
	counts := ins.Args[0]
	if counts.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(counts, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s count register must match the destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(counts) {
		return true, false, fmt.Errorf("amd64 %s counts must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}
	if suffixes.broadcast && !isAMD64MemoryOperand(counts) {
		return true, false, fmt.Errorf("amd64 %s.BCST requires a memory count source: %q", baseOp, ins.Raw)
	}

	mask := ""
	if masked {
		maskArg := ins.Args[2]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, validMask := amd64ParseKReg(maskArg.Reg)
		if !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	lanes := byteWidth * 8 / spec.laneBits
	countValues, err := c.loadMaskedPackedCompareLanes(counts, byteWidth, spec.laneBits, suffixes.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	dataValues, err := c.loadPackedCompareLanes(data, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	result := c.emitPerLaneVariableShift(spec, lanes, countValues, dataValues)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, suffixes.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPerLaneVariableShift(spec amd64PerLaneVariableShiftSpec, lanes int, counts, data string) string {
	typeName := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	limit := amd64SplatInteger(c, lanes, spec.laneBits, fmt.Sprintf("%d", spec.laneBits))
	inRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", inRange, typeName, counts, limit)
	fallbackCount := "zeroinitializer"
	if spec.arithmetic {
		fallbackCount = amd64SplatInteger(c, lanes, spec.laneBits, fmt.Sprintf("%d", spec.laneBits-1))
	}
	safeCounts := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", safeCounts, lanes, inRange, typeName, counts, typeName, fallbackCount)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", shifted, spec.operation, typeName, data, safeCounts)
	if spec.arithmetic {
		return "%" + shifted
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s zeroinitializer\n", result, lanes, inRange, typeName, shifted, typeName)
	return "%" + result
}
