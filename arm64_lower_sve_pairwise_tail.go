package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVETailOps = map[Op]string{
	"ZADDPT": "addpt",
	"ZSUBPT": "subpt",
}

func (c *arm64Ctx) lowerARM64SVEPairwiseTail(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op == "ZADDP" {
		return c.lowerARM64SVEAddPairwise(ins)
	}
	intrinsic, ok := arm64SVETailOps[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || (len(ins.Args) != 3 && len(ins.Args) != 4) {
		return true, false, fmt.Errorf("arm64 %s expects one of its two D-width Go 1.27 forms without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !secondOK || !firstOK || secondBits != 64 || firstBits != 64 {
		return true, false, fmt.Errorf("arm64 %s requires D-width vector operands: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, 64)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, 64)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if len(ins.Args) == 3 {
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !destinationOK || destinationBits != 64 {
			return true, false, fmt.Errorf("arm64 %s unpredicated form requires a D-width destination: %q", op, ins.Raw)
		}
		assembly := intrinsic + " $0.d, $1.d, $2.d"
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s)\n", result, vectorType, assembly, "=w,w,w", vectorType, firstValue, vectorType, secondValue)
		return true, false, c.storeZRegElements(destination, 64, "%"+result)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !predicateOK || !destinationOK || destinationBits != 64 || destination != first {
		return true, false, fmt.Errorf("arm64 %s predicated form requires Pg/M and a repeated D-width destination: %q", op, ins.Raw)
	}
	predicateValue, err := c.loadPReg(predicate)
	if err != nil {
		return true, false, err
	}
	assembly := intrinsic + " $0.d, $3/m, $0.d, $2.d"
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, <vscale x 16 x i1> %s)\n", result, vectorType, assembly, "=&w,0,w,@3Upl", vectorType, firstValue, vectorType, secondValue, predicateValue)
	return true, false, c.storeZRegElements(destination, 64, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEAddPairwise(ins Instr) (ok bool, terminated bool, err error) {
	if strings.ToUpper(string(ins.Op)) != "ZADDP" || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZADDP expects Zm.T, Zdn.T, Pg/M, Zdn.T without a suffix: %q", ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
		return true, false, fmt.Errorf("arm64 ZADDP requires matching element widths and a repeated destructive destination: %q", ins.Raw)
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
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.addp.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, lanes, firstBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}
