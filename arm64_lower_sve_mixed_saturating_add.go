package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEMixedSaturatingAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic := ""
	switch op {
	case "ZSUQADD":
		intrinsic = "suqadd"
	case "ZUSQADD":
		intrinsic = "usqadd"
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.B|H|S|D, Zdn.B|H|S|D, P0..P7/M, Zdn.B|H|S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || destinationBits != firstBits || destination != first {
		return true, false, fmt.Errorf("arm64 %s requires matching-width destructive B/H/S/D operands and P0..P7/M: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %%%s, %s %s\n", selected, predicateType, predicateValue, vectorType, result, vectorType, firstValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+selected)
}
