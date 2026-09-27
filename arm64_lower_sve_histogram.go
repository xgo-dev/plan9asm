package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEHistogramOps = map[Op]struct{}{
	"ZHISTCNT": {},
	"ZHISTSEG": {},
}

func (c *arm64Ctx) lowerARM64SVEHistogram(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, ok := arm64SVEHistogramOps[op]; !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept a mnemonic suffix: %q", op, ins.Raw)
	}
	if op == "ZHISTSEG" {
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 ZHISTSEG expects Zm.B, Zn.B, Zd.B: %q", ins.Raw)
		}
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != 8 || firstBits != 8 || destinationBits != 8 {
			return true, false, fmt.Errorf("arm64 ZHISTSEG requires three B scalable-vector operands: %q", ins.Raw)
		}
		firstValue, vectorType, err := c.loadZRegElements(first, 8)
		if err != nil {
			return true, false, err
		}
		secondValue, _, err := c.loadZRegElements(second, 8)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.histseg.nxv16i8(%s %s, %s %s)\n", result, vectorType, vectorType, firstValue, vectorType, secondValue)
		return true, false, c.storeZRegElements(destination, 8, "%"+result)
	}
	if len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZHISTCNT expects Zm.S|D, Zn.S|D, Pg/Z, Zd.S|D: %q", ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "Z", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || (firstBits != 32 && firstBits != 64) || secondBits != firstBits || destinationBits != firstBits {
		return true, false, fmt.Errorf("arm64 ZHISTCNT requires matching S/D vectors under P0..P7/Z: %q", ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, firstBits)
	if err != nil {
		return true, false, err
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.histcnt.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
