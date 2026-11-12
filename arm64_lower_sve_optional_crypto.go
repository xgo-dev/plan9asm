package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEOptionalCryptoSpec struct {
	intrinsic   string
	elementBits int
	destructive bool
	feature     string
}

var arm64SVEOptionalCryptoSpecs = map[Op]arm64SVEOptionalCryptoSpec{
	"ZRAX1":    {intrinsic: "rax1", elementBits: 64, feature: "+sve2-sha3"},
	"ZSM4E":    {intrinsic: "sm4e", elementBits: 32, destructive: true, feature: "+sve2-sm4"},
	"ZSM4EKEY": {intrinsic: "sm4ekey", elementBits: 32, feature: "+sve2-sm4"},
}

func (c *arm64Ctx) lowerARM64SVEOptionalCrypto(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEOptionalCryptoSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three vector operands without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !secondOK || !firstOK || !destinationOK || secondBits != spec.elementBits || firstBits != spec.elementBits || destinationBits != spec.elementBits || spec.destructive && first != destination {
		return true, false, fmt.Errorf("arm64 %s requires matching %d-bit vectors%s: %q", op, spec.elementBits, map[bool]string{true: " with repeated source/destination", false: ""}[spec.destructive], ins.Raw)
	}
	firstValue, vectorType, err := c.loadZRegElements(first, spec.elementBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadZRegElements(second, spec.elementBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s, %s %s)\n", result, vectorType, spec.intrinsic, vectorType, firstValue, vectorType, secondValue)
	return true, false, c.storeZRegElements(destination, spec.elementBits, "%"+result)
}
