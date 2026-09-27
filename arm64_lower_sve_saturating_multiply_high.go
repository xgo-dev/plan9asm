package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVESaturatingMultiplyHighIntrinsics = map[Op]string{
	"ZSQDMULH":  "sqdmulh",
	"ZSQRDMULH": "sqrdmulh",
}

func (c *arm64Ctx) lowerARM64SVESaturatingMultiplyHigh(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVESaturatingMultiplyHighIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector form without a suffix: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !firstOK || !destinationOK || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s source and destination widths must match: %q", op, ins.Raw)
	}
	second, secondBits, lane, indexed := arm64ParseSVEZIndexedElementReg(ins.Args[0])
	if !indexed {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		if !secondOK || secondBits != firstBits {
			return true, false, fmt.Errorf("arm64 %s vector operands must use one B/H/S/D width: %q", op, ins.Raw)
		}
		return true, false, c.lowerARM64SVESaturatingMultiplyHighForm(intrinsic, firstBits, first, second, 0, destination, false)
	}
	if secondBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s indexed operands must use one H/S/D width and an encodable lane: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVESaturatingMultiplyHighForm(intrinsic, firstBits, first, second, lane, destination, true)
}

func (c *arm64Ctx) lowerARM64SVESaturatingMultiplyHighForm(intrinsic string, elementBits, first, second, lane, destination int, indexed bool) error {
	firstValue, vectorType, err := c.loadZRegElements(first, elementBits)
	if err != nil {
		return err
	}
	secondValue, _, err := c.loadZRegElements(second, elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, i32 %d)\n",
			result, vectorType, intrinsic, lanes, elementBits, vectorType, firstValue, vectorType, secondValue, lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n",
			result, vectorType, intrinsic, lanes, elementBits, vectorType, firstValue, vectorType, secondValue)
	}
	return c.storeZRegElements(destination, elementBits, "%"+result)
}
