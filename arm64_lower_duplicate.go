package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64VectorDuplicate implements all three AVDUP rows in Go's ARM64
// optab: vector lane to arranged vector, vector lane to scalar V register, and
// integer register to arranged vector.
func (c *arm64Ctx) lowerARM64VectorDuplicate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VDUP" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "VDUP" || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 VDUP expects a vector lane or R/ZR source and a vector destination, with no suffix: %q", ins.Raw)
	}

	src, dst := ins.Args[0].Reg, ins.Args[1].Reg
	dstArrangement, arrangedDst := parseARM64VectorArrangement(dst)
	if arrangedDst && !arm64VDUPArrangementAllowed(dstArrangement) {
		return true, false, fmt.Errorf("arm64 VDUP destination arrangement is outside Go's optab: %q", ins.Raw)
	}

	_, lane, laneSource := arm64ParseVRegLane(src)
	if laneSource {
		if arrangedDst {
			// Go's case 79 encoder intentionally derives the source element width
			// from the destination arrangement, not from the source's spelling.
			// Match that behavior even for accepted mixed-suffix forms.
			if lane >= 128/dstArrangement.elementBits {
				return true, false, fmt.Errorf("arm64 VDUP source lane is out of range for destination arrangement: %q", ins.Raw)
			}
			element, err := c.arm64VDUPExtractLane(src, dstArrangement.elementBits, lane)
			if err != nil {
				return true, false, err
			}
			vector := c.arm64VDUPSplat(dstArrangement, element)
			return true, false, c.storeARM64VectorInteger(dst, dstArrangement, vector)
		}

		if strings.Contains(string(dst), ".") {
			return true, false, fmt.Errorf("arm64 VDUP destination arrangement is outside Go's optab: %q", ins.Raw)
		}
		if _, valid := arm64ParseVReg(dst); !valid {
			return true, false, fmt.Errorf("arm64 VDUP lane destination must be a bare V register: %q", ins.Raw)
		}
		kind, _, _ := arm64ParseVRegLane(src)
		bits := map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[kind]
		element, err := c.arm64VDUPExtractLane(src, bits, lane)
		if err != nil {
			return true, false, err
		}
		physicalLanes := 128 / bits
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n", inserted, physicalLanes, bits, bits, element)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytes, physicalLanes, bits, inserted)
		return true, false, c.storeVReg(dst, "%"+bytes)
	}

	if !arrangedDst || !isARM64GeneralOrZeroReg(src) {
		return true, false, fmt.Errorf("arm64 VDUP expects a vector lane or R/ZR source and a valid arranged vector destination: %q", ins.Raw)
	}
	value, err := c.loadReg(src)
	if err != nil {
		return true, false, err
	}
	if dstArrangement.elementBits < 64 {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", truncated, value, dstArrangement.elementBits)
		value = "%" + truncated
	}
	vector := c.arm64VDUPSplat(dstArrangement, value)
	return true, false, c.storeARM64VectorInteger(dst, dstArrangement, vector)
}

func arm64VDUPArrangementAllowed(arrangement arm64VectorArrangement) bool {
	return (arrangement.elementBits == 8 && (arrangement.lanes == 8 || arrangement.lanes == 16)) ||
		(arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8)) ||
		(arrangement.elementBits == 32 && (arrangement.lanes == 2 || arrangement.lanes == 4)) ||
		(arrangement.elementBits == 64 && arrangement.lanes == 2)
}

func (c *arm64Ctx) arm64VDUPExtractLane(src Reg, bits, lane int) (string, error) {
	bytes, err := c.loadVReg(src)
	if err != nil {
		return "", err
	}
	lanes := 128 / bits
	typed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", typed, bytes, lanes, bits)
	element := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %%%s, i32 %d\n", element, lanes, bits, typed, lane)
	return "%" + element, nil
}

func (c *arm64Ctx) arm64VDUPSplat(arrangement arm64VectorArrangement, element string) string {
	seed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> poison, i%d %s, i32 0\n", seed, arrangement.lanes, arrangement.elementBits, arrangement.elementBits, element)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %%%s, <%d x i%d> poison, <%d x i32> zeroinitializer\n",
		result, arrangement.lanes, arrangement.elementBits, seed, arrangement.lanes, arrangement.elementBits, arrangement.lanes)
	return "%" + result
}
