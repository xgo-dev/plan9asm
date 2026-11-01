package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEComplexAddIntrinsics = map[Op]string{
	"ZCADD":   "cadd.x",
	"ZSQCADD": "sqcadd.x",
}

func (c *arm64Ctx) lowerARM64SVEComplexAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEComplexAddIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects $90|$270, Zm.T, Zdn.T, Zdn.T without a suffix: %q", op, ins.Raw)
	}
	rotation := ins.Args[0].Imm
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	repeatedDestination, repeatedBits, repeatedOK := arm64ParseSVEZElementReg(ins.Args[3])
	if (rotation != 90 && rotation != 270) || !secondOK || !destinationOK || !repeatedOK || secondBits != destinationBits || repeatedBits != destinationBits || repeatedDestination != destination {
		return true, false, fmt.Errorf("arm64 %s requires rotation $90/$270 and matching destructive B/H/S/D operands: %q", op, ins.Raw)
	}
	destinationValue, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, secondBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, i32 %d)\n", result, vectorType, intrinsic, lanes, destinationBits, vectorType, destinationValue, vectorType, secondValue, rotation)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
