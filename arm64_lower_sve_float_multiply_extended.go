package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEFloatMultiplyExtended(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFMULX" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZFMULX expects one complete Go 1.27 predicated form without a suffix: %q", ins.Raw)
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
		return true, false, fmt.Errorf("arm64 ZFMULX requires matching destructive H/S/D operands and P0..P7.M: %q", ins.Raw)
	}
	firstValue, vectorType, err := c.loadRawSVEFloatVector(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, firstBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, _ := arm64SVEFloatType(firstBits)
	code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[firstBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fmulx.nxv%d%s(%s %s, %s %s, %s %s)\n",
		result, vectorType, lanes, code, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeRawSVEFloatVector(destination, firstBits, "%"+result, vectorType)
}
