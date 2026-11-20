package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEEORInterleaveIntrinsics = map[Op]string{
	"ZEORBT": "eorbt",
	"ZEORTB": "eortb",
}

func (c *arm64Ctx) lowerARM64SVEEORInterleave(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEEORInterleaveIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zn.T, Zd.T without a suffix: %q", op, ins.Raw)
	}
	third, thirdBits, thirdOK := arm64ParseSVEZElementReg(ins.Args[0])
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !thirdOK || !secondOK || !destinationOK || thirdBits != secondBits || secondBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s operands must use one matching B/H/S/D width: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, destinationBits)
	if err != nil {
		return true, false, err
	}
	thirdValue, _, err := c.loadZRegElements(third, destinationBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, firstValue, vectorType, secondValue, vectorType, thirdValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
