package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEPMULLIntrinsics = map[Op]string{
	"ZPMULLB": "pmullb.pair",
	"ZPMULLT": "pmullt.pair",
}

func arm64SVEPMULLNeedsSVE2AES(ins Instr) bool {
	if len(ins.Args) != 3 {
		return false
	}
	_, ok := arm64ParseSVEZQReg(ins.Args[2])
	return ok
}

func (c *arm64Ctx) lowerARM64SVEPMULL(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEPMULLIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.B, Zn.B, Zd.H; Zm.S, Zn.S, Zd.D; or Zm.D, Zn.D, Zd.Q without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !secondOK || !firstOK || secondBits != firstBits || firstBits != 8 && firstBits != 32 && firstBits != 64 {
		return true, false, fmt.Errorf("arm64 %s requires matching B, S, or D source vectors: %q", op, ins.Raw)
	}
	destinationRepresentationBits := firstBits * 2
	destination := 0
	if firstBits == 64 {
		var destinationOK bool
		destination, destinationOK = arm64ParseSVEZQReg(ins.Args[2])
		if !destinationOK {
			return true, false, fmt.Errorf("arm64 %s D sources require a Q destination: %q", op, ins.Raw)
		}
		destinationRepresentationBits = 64
	} else {
		var destinationBits int
		var destinationOK bool
		destination, destinationBits, destinationOK = arm64ParseSVEZElementReg(ins.Args[2])
		if !destinationOK || destinationBits != destinationRepresentationBits {
			return true, false, fmt.Errorf("arm64 %s must widen B to H or S to D: %q", op, ins.Raw)
		}
	}
	firstValue, sourceType, err := c.loadZRegElements(first, firstBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, firstBits)
	if err != nil {
		return true, false, err
	}
	_, sourceLanes, err := arm64SVEVectorType(firstBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, sourceType, intrinsic, sourceLanes, firstBits, sourceType, firstValue, sourceType, secondValue)
	resultValue := "%" + result
	if firstBits != 64 {
		destinationType, _, err := arm64SVEVectorType(destinationRepresentationBits)
		if err != nil {
			return true, false, err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", converted, sourceType, resultValue, destinationType)
		resultValue = "%" + converted
	}
	return true, false, c.storeZRegElements(destination, destinationRepresentationBits, resultValue)
}
