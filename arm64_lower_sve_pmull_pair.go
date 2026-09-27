package plan9asm

import (
	"fmt"
	"strings"
)

func arm64ParseSVEQPair(operand Operand) (first, second int, ok bool) {
	if operand.Kind != OpRegList || !operand.RegListRange || len(operand.RegList) != 2 {
		return 0, 0, false
	}
	first, firstOK := arm64ParseSVEZQReg(Operand{Kind: OpReg, Reg: operand.RegList[0]})
	second, secondOK := arm64ParseSVEZQReg(Operand{Kind: OpReg, Reg: operand.RegList[1]})
	return first, second, firstOK && secondOK && first%2 == 0 && second == first+1
}

func (c *arm64Ctx) lowerARM64SVEPMULLPair(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZPMULL" && op != "ZPMLAL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.D, Zn.D, [Zd.Q-Zd+1.Q] without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	firstDestination, secondDestination, destinationOK := arm64ParseSVEQPair(ins.Args[2])
	if !secondOK || !firstOK || secondBits != 64 || firstBits != 64 || !destinationOK {
		return true, false, fmt.Errorf("arm64 %s requires D sources and an even-odd consecutive Q destination pair: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, 64)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, 64)
	if err != nil {
		return true, false, err
	}
	aggregateType := fmt.Sprintf("{ %s, %s }", vectorType, vectorType)
	result := c.newTmp()
	if op == "ZPMULL" {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmull.pair.x2(%s %s, %s %s)\n", result, aggregateType, vectorType, firstValue, vectorType, secondValue)
	} else {
		firstAccumulator, _, err := c.loadZRegElements(firstDestination, 64)
		if err != nil {
			return true, false, err
		}
		secondAccumulator, _, err := c.loadZRegElements(secondDestination, 64)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.pmlal.pair.x2(%s %s, %s %s, %s %s, %s %s)\n", result, aggregateType, vectorType, firstAccumulator, vectorType, secondAccumulator, vectorType, firstValue, vectorType, secondValue)
	}
	firstResult := c.newTmp()
	secondResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", firstResult, aggregateType, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", secondResult, aggregateType, result)
	if err := c.storeZRegElements(firstDestination, 64, "%"+firstResult); err != nil {
		return true, false, err
	}
	return true, false, c.storeZRegElements(secondDestination, 64, "%"+secondResult)
}
