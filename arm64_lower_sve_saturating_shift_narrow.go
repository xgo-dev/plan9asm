package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVESaturatingShiftNarrowSpec struct {
	intrinsic string
	top       bool
}

var arm64SVESaturatingShiftNarrowSpecs = map[Op]arm64SVESaturatingShiftNarrowSpec{
	"ZSQSHRNB":   {intrinsic: "sqshrnb"},
	"ZSQSHRNT":   {intrinsic: "sqshrnt", top: true},
	"ZSQRSHRNB":  {intrinsic: "sqrshrnb"},
	"ZSQRSHRNT":  {intrinsic: "sqrshrnt", top: true},
	"ZSQSHRUNB":  {intrinsic: "sqshrunb"},
	"ZSQSHRUNT":  {intrinsic: "sqshrunt", top: true},
	"ZSQRSHRUNB": {intrinsic: "sqrshrunb"},
	"ZSQRSHRUNT": {intrinsic: "sqrshrunt", top: true},
	"ZUQSHRNB":   {intrinsic: "uqshrnb"},
	"ZUQSHRNT":   {intrinsic: "uqshrnt", top: true},
	"ZUQRSHRNB":  {intrinsic: "uqrshrnb"},
	"ZUQRSHRNT":  {intrinsic: "uqrshrnt", top: true},
}

func (c *arm64Ctx) lowerARM64SVESaturatingShiftNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVESaturatingShiftNarrowSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Zn.H|S|D, Zd.B|H|S without a suffix: %q", op, ins.Raw)
	}
	shift := ins.Args[0].Imm
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !destinationOK || (sourceBits != 16 && sourceBits != 32 && sourceBits != 64) || destinationBits*2 != sourceBits || shift < 1 || shift > int64(destinationBits) {
		return true, false, fmt.Errorf("arm64 %s requires matching H-to-B, S-to-H, or D-to-S operands and shift $1..$destinationBits: %q", op, ins.Raw)
	}
	sourceValue, sourceType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	destinationType, _, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	args := fmt.Sprintf("%s %s, i32 %d", sourceType, sourceValue, shift)
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
