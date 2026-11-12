package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEUnpackIntrinsics = map[Op]string{
	"ZSUNPKHI": "sunpkhi",
	"ZSUNPKLO": "sunpklo",
	"ZUUNPKHI": "uunpkhi",
	"ZUUNPKLO": "uunpklo",
}

func (c *arm64Ctx) lowerARM64SVEUnpack(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEUnpackIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.B|H|S, Zd.H|S|D without a suffix: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !sourceOK || !destinationOK || (sourceBits != 8 && sourceBits != 16 && sourceBits != 32) || destinationBits != sourceBits*2 {
		return true, false, fmt.Errorf("arm64 %s requires a B-to-H, H-to-S, or S-to-D widening pair: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	destinationLanes := 128 / destinationBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s)\n", result, destinationType, intrinsic, destinationLanes, destinationBits, sourceType, sourceValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
