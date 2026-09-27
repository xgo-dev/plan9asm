package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEFloatTrigMultiplyAdd(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFTMAD" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 ZFTMAD expects one complete Go 1.27 vector form without a suffix: %q", ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 7 {
		return true, false, fmt.Errorf("arm64 ZFTMAD immediate must be an unsigned 3-bit integer: %q", ins.Raw)
	}
	multiplier, multiplierBits, multiplierOK := arm64SVEFloatElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	repeated, repeatedBits, repeatedOK := arm64SVEFloatElementReg(ins.Args[3])
	if !multiplierOK || !destinationOK || !repeatedOK || multiplierBits != destinationBits || destinationBits != repeatedBits || destination != repeated {
		return true, false, fmt.Errorf("arm64 ZFTMAD requires matching destructive H/S/D operands: %q", ins.Raw)
	}
	destinationValue, vectorType, err := c.loadRawSVEFloatVector(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	multiplierValue, _, err := c.loadRawSVEFloatVector(multiplier, multiplierBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, _ := arm64SVEFloatType(destinationBits)
	code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[destinationBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ftmad.x.nxv%d%s(%s %s, %s %s, i32 %d)\n",
		result, vectorType, lanes, code, vectorType, destinationValue, vectorType, multiplierValue, ins.Args[0].Imm)
	return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, vectorType)
}
