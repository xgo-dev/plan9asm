package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVESaturatingNarrowSpec struct {
	intrinsic string
	top       bool
}

var arm64SVESaturatingNarrowSpecs = map[Op]arm64SVESaturatingNarrowSpec{
	"ZSQXTNB":  {intrinsic: "sqxtnb"},
	"ZSQXTNT":  {intrinsic: "sqxtnt", top: true},
	"ZSQXTUNB": {intrinsic: "sqxtunb"},
	"ZSQXTUNT": {intrinsic: "sqxtunt", top: true},
	"ZUQXTNB":  {intrinsic: "uqxtnb"},
	"ZUQXTNT":  {intrinsic: "uqxtnt", top: true},
}

func (c *arm64Ctx) lowerARM64SVESaturatingNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVESaturatingNarrowSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.H|S|D, Zd.B|H|S without a suffix: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !sourceOK || !destinationOK || (sourceBits != 16 && sourceBits != 32 && sourceBits != 64) || destinationBits*2 != sourceBits {
		return true, false, fmt.Errorf("arm64 %s requires an H-to-B, S-to-H, or D-to-S narrowing pair: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	args := fmt.Sprintf("%s %s", sourceType, sourceValue)
	if spec.top {
		merged, _, err := c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
		args = fmt.Sprintf("%s %s, %s", destinationType, merged, args)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n", result, destinationType, spec.intrinsic, 128/sourceBits, sourceBits, args)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
