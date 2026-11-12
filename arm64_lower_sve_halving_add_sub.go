package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEHalvingAddSubIntrinsics = map[Op]string{
	"ZSHADD":  "shadd",
	"ZSRHADD": "srhadd",
	"ZUHADD":  "uhadd",
	"ZURHADD": "urhadd",
	"ZSHSUB":  "shsub",
	"ZSHSUBR": "shsubr",
	"ZUHSUB":  "uhsub",
	"ZUHSUBR": "uhsubr",
}

func (c *arm64Ctx) lowerARM64SVEHalvingAddSub(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEHalvingAddSubIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zdn.T, P0..P7/M, Zdn.T without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
		return true, false, fmt.Errorf("arm64 %s requires matching-width destructive data operands and P0..P7/M: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
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
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}
