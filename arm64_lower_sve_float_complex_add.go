package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEFloatComplexAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFCADD" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 5 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 ZFCADD expects $90|$270, Zm.H|S|D, Zdn.H|S|D, P0..P7/M, Zdn.H|S|D without a suffix: %q", ins.Raw)
	}
	rotation := ins.Args[0].Imm
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[1])
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[2])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[3], "M", 7)
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[4])
	if (rotation != 90 && rotation != 270) || !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || destinationBits != firstBits || destination != first {
		return true, false, fmt.Errorf("arm64 ZFCADD requires rotation $90/$270, matching destructive H/S/D operands, and P0..P7/M: %q", ins.Raw)
	}
	firstValue, vectorType, err := c.loadRawSVEFloatVector(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, secondBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, err := arm64SVEFloatType(firstBits)
	if err != nil {
		return true, false, err
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[firstBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fcadd.nxv%d%s(%s %s, %s %s, %s %s, i32 %d)\n", result, vectorType, lanes, mangle, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue, rotation)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %%%s, %s %s\n", selected, predicateType, predicateValue, vectorType, result, vectorType, firstValue)
	return true, false, c.storeRawSVEFloatVector(destination, firstBits, "%"+selected, vectorType)
}
