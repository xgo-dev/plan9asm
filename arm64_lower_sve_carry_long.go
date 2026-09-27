package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVECarryLongIntrinsics = map[Op]string{
	"ZADCLB": "adclb",
	"ZADCLT": "adclt",
	"ZSBCLB": "sbclb",
	"ZSBCLT": "sbclt",
}

func (c *arm64Ctx) lowerARM64SVECarryLong(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVECarryLongIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.S|D, Zn.S|D, Zda.S|D without a suffix: %q", op, ins.Raw)
	}
	third, thirdBits, thirdOK := arm64ParseSVEZElementReg(ins.Args[0])
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	accumulator, accumulatorBits, accumulatorOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !thirdOK || !secondOK || !accumulatorOK || (accumulatorBits != 32 && accumulatorBits != 64) || secondBits != accumulatorBits || thirdBits != accumulatorBits {
		return true, false, fmt.Errorf("arm64 %s requires matching S/D operands: %q", op, ins.Raw)
	}
	accumulatorValue, vectorType, err := c.loadZRegElements(accumulator, accumulatorBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, accumulatorBits)
	if err != nil {
		return true, false, err
	}
	thirdValue, _, err := c.loadZRegElements(third, accumulatorBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / accumulatorBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, accumulatorBits, vectorType, accumulatorValue, vectorType, secondValue, vectorType, thirdValue)
	return true, false, c.storeZRegElements(accumulator, accumulatorBits, "%"+result)
}
