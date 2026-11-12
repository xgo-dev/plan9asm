package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEMultiplyAddTailOps = map[Op]string{
	"ZMADPT": "madpt",
	"ZMLAPT": "mlapt",
}

func (c *arm64Ctx) lowerARM64SVEMultiplyAddTail(op Op, ins Instr) (ok bool, terminated bool, err error) {
	mnemonic, ok := arm64SVEMultiplyAddTailOps[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three D-width vector operands without a suffix: %q", op, ins.Raw)
	}
	firstSource, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0])
	secondSource, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !firstOK || !secondOK || !destinationOK || firstBits != 64 || secondBits != 64 || destinationBits != 64 {
		return true, false, fmt.Errorf("arm64 %s requires three D-width scalable-vector operands: %q", op, ins.Raw)
	}
	destinationValue, vectorType, err := c.loadZRegElements(destination, 64)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(secondSource, 64)
	if err != nil {
		return true, false, err
	}
	firstValue, _, err := c.loadZRegElements(firstSource, 64)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	assembly := mnemonic + " $0.d, $2.d, $3.d"
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, %s %s)\n", result, vectorType, assembly, "=&w,0,w,w", vectorType, destinationValue, vectorType, secondValue, vectorType, firstValue)
	return true, false, c.storeZRegElements(destination, 64, "%"+result)
}
