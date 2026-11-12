package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEFloatReciprocalStepIntrinsics = map[Op]string{
	"ZFRECPS":  "frecps.x",
	"ZFRSQRTS": "frsqrts.x",
}

func (c *arm64Ctx) lowerARM64SVEFloatReciprocalStep(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEFloatReciprocalStepIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.H|S|D, Zn.H|S|D, Zd.H|S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s requires three matching H/S/D scalable floating-vector operands: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadRawSVEFloatVector(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, secondBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, err := arm64SVEFloatType(firstBits)
	if err != nil {
		return true, false, err
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[firstBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s)\n", result, vectorType, intrinsic, lanes, mangle, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, vectorType)
}
