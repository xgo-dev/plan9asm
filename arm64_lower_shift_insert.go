package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorShiftInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VSRI" && op != "VSLI" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Vsrc.<T>, Vdst.<T> and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[2].Reg)
	allowed := func(a arm64VectorArrangement) bool {
		return (a.elementBits == 8 && (a.lanes == 8 || a.lanes == 16)) ||
			(a.elementBits == 16 && (a.lanes == 4 || a.lanes == 8)) ||
			(a.elementBits == 32 && (a.lanes == 2 || a.lanes == 4)) ||
			(a.elementBits == 64 && a.lanes == 2)
	}
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement || !allowed(sourceArrangement) {
		return true, false, fmt.Errorf("arm64 %s requires matching B8/B16/H4/H8/S2/S4/D2 arrangements: %q", op, ins.Raw)
	}
	shift := ins.Args[0].Imm
	if op == "VSRI" {
		if shift < 1 || shift > int64(sourceArrangement.elementBits) {
			return true, false, fmt.Errorf("arm64 VSRI shift must be in [1,%d]: %q", sourceArrangement.elementBits, ins.Raw)
		}
	} else if shift < 0 || shift >= int64(sourceArrangement.elementBits) {
		return true, false, fmt.Errorf("arm64 VSLI shift must be in [0,%d]: %q", sourceArrangement.elementBits-1, ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[1].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	destination, err := c.loadARM64VectorInteger(ins.Args[2].Reg, destinationArrangement)
	if err != nil {
		return true, false, err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	result := source
	if op == "VSRI" {
		if shift == int64(sourceArrangement.elementBits) {
			result = destination
		} else {
			lowBits := int64(sourceArrangement.elementBits) - shift
			high := c.newTmp()
			preserved := c.newTmp()
			inserted := c.newTmp()
			combined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", high, vectorType, destination, arm64VectorIntegerSplat(sourceArrangement, lowBits))
			fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", preserved, vectorType, high, arm64VectorIntegerSplat(sourceArrangement, lowBits))
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", inserted, vectorType, source, arm64VectorIntegerSplat(sourceArrangement, shift))
			fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", combined, vectorType, preserved, inserted)
			result = "%" + combined
		}
	} else if shift > 0 {
		preserved := c.newTmp()
		inserted := c.newTmp()
		combined := c.newTmp()
		lowMask := int64((uint64(1) << uint(shift)) - 1)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", preserved, vectorType, destination, arm64VectorIntegerSplat(sourceArrangement, lowMask))
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", inserted, vectorType, source, arm64VectorIntegerSplat(sourceArrangement, shift))
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", combined, vectorType, preserved, inserted)
		result = "%" + combined
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, destinationArrangement, result)
}
