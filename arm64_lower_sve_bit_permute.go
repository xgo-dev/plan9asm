package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEBitPermuteIntrinsics = map[Op]string{
	"ZBDEP": "bdep.x",
	"ZBEXT": "bext.x",
	"ZBGRP": "bgrp.x",
}

func (c *arm64Ctx) lowerARM64SVEBitPermute(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEBitPermuteIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.T, Zn.T, Zd.T without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || firstBits != secondBits || destinationBits != firstBits {
		return true, false, fmt.Errorf("arm64 %s requires matching B/H/S/D operands: %q", op, ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / firstBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, vectorType, intrinsic, lanes, firstBits, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, firstBits, "%"+result)
}
