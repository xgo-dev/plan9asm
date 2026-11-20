package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEPMUL(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZPMUL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZPMUL expects Zm.B, Zn.B, Zd.B without a suffix: %q", ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != 8 || firstBits != 8 || destinationBits != 8 {
		return true, false, fmt.Errorf("arm64 ZPMUL requires B-element vectors: %q", ins.Raw)
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
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmul.nxv16i8(%s %s, %s %s)\n", result, vectorType, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, 8, "%"+result)
}
