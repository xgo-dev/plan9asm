package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEFloatTrigIntrinsics = map[Op]string{
	"ZFTSMUL": "ftsmul",
	"ZFTSSEL": "ftssel",
}

func (c *arm64Ctx) lowerARM64SVEFloatTrigMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEFloatTrigIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 vector form without a suffix: %q", op, ins.Raw)
	}
	control, controlBits, controlOK := arm64SVEFloatElementReg(ins.Args[0])
	source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
	if !controlOK || !sourceOK || !destinationOK || controlBits != sourceBits || sourceBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s operands must use one H/S/D width: %q", op, ins.Raw)
	}
	sourceValue, floatVectorType, err := c.loadRawSVEFloatVector(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	controlValue, integerVectorType, err := c.loadZRegElements(control, controlBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, _ := arm64SVEFloatType(sourceBits)
	code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[sourceBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.x.nxv%d%s(%s %s, %s %s)\n",
		result, floatVectorType, intrinsic, lanes, code, floatVectorType, sourceValue, integerVectorType, controlValue)
	return true, false, c.storeRawSVEFloatVector(destination, sourceBits, "%"+result, floatVectorType)
}
