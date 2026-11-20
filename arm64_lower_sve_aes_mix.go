package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEAESMixIntrinsics = map[Op]string{
	"ZAESIMC": "aesimc",
	"ZAESMC":  "aesmc",
}

func (c *arm64Ctx) lowerARM64SVEAESMix(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEAESMixIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Zdn.B, Zdn.B without a suffix: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !firstOK || !destinationOK || firstBits != 8 || destinationBits != 8 || first != destination {
		return true, false, fmt.Errorf("arm64 %s requires the same B-element source/destination register: %q", op, ins.Raw)
	}
	value, vectorType, err := c.loadZRegElements(destination, 8)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s)\n", result, vectorType, intrinsic, vectorType, value)
	return true, false, c.storeZRegElements(destination, 8, "%"+result)
}
