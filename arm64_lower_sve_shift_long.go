package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEShiftLongIntrinsics = map[Op]string{
	"ZSSHLLB": "sshllb",
	"ZSSHLLT": "sshllt",
	"ZUSHLLB": "ushllb",
	"ZUSHLLT": "ushllt",
}

func (c *arm64Ctx) lowerARM64SVEShiftLong(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEShiftLongIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Zn.B|H|S, Zd.H|S|D without a suffix: %q", op, ins.Raw)
	}
	shift := ins.Args[0].Imm
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !destinationOK || sourceBits == 64 || destinationBits != sourceBits*2 || shift < 0 || shift >= int64(sourceBits) {
		return true, false, fmt.Errorf("arm64 %s requires B-to-H, H-to-S, or S-to-D operands and shift $0..$sourceBits-1: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, destinationLanes, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, i32 %d)\n", result, destinationType, intrinsic, destinationLanes, destinationBits, sourceType, sourceValue, shift)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
