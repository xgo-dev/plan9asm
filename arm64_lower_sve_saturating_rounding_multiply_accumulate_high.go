package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVESaturatingRoundingMultiplyAccumulateHighIntrinsics = map[Op]string{
	"ZSQRDMLAH": "sqrdmlah",
	"ZSQRDMLSH": "sqrdmlsh",
}

func (c *arm64Ctx) lowerARM64SVESaturatingRoundingMultiplyAccumulateHigh(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVESaturatingRoundingMultiplyAccumulateHighIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector form without a suffix: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !firstOK || !destinationOK || firstBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s source and accumulator widths must match: %q", op, ins.Raw)
	}
	second, secondBits, lane, indexed := arm64ParseSVEZIndexedElementReg(ins.Args[0])
	if !indexed {
		var secondOK bool
		second, secondBits, secondOK = arm64ParseSVEZElementReg(ins.Args[0])
		if !secondOK || secondBits != firstBits {
			return true, false, fmt.Errorf("arm64 %s vector operands must use one B/H/S/D width: %q", op, ins.Raw)
		}
	} else if secondBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s indexed operands must use one H/S/D width and an encodable lane: %q", op, ins.Raw)
	}
	accumulator, vectorType, err := c.loadZRegElements(destination, firstBits)
	if err != nil {
		return true, false, err
	}
	firstValue, _, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	_, lanes, err := arm64SVEVectorType(firstBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n",
			result, vectorType, intrinsic, lanes, firstBits, vectorType, accumulator, vectorType, firstValue, vectorType, secondValue, lane)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n",
			result, vectorType, intrinsic, lanes, firstBits, vectorType, accumulator, vectorType, firstValue, vectorType, secondValue)
	}
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}
