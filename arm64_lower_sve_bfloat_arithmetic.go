package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEBFloatArithmeticSpec struct {
	intrinsic    string
	unpredicated bool
	indexed      bool
	scale        bool
}

var arm64SVEBFloatArithmeticSpecs = map[Op]arm64SVEBFloatArithmeticSpec{
	"ZBFADD":   {intrinsic: "fadd", unpredicated: true},
	"ZBFSUB":   {intrinsic: "fsub", unpredicated: true},
	"ZBFMUL":   {intrinsic: "fmul", unpredicated: true, indexed: true},
	"ZBFMAX":   {intrinsic: "fmax"},
	"ZBFMAXNM": {intrinsic: "fmaxnm"},
	"ZBFMIN":   {intrinsic: "fmin"},
	"ZBFMINNM": {intrinsic: "fminnm"},
	"ZBFSCALE": {intrinsic: "fscale", scale: true},
}

func (c *arm64Ctx) lowerARM64SVEBFloatArithmetic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEBFloatArithmeticSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) == 4 {
		return c.lowerARM64SVEBFloatArithmeticPredicated(op, spec, ins)
	}
	if len(ins.Args) == 3 && spec.unpredicated {
		return c.lowerARM64SVEBFloatArithmeticUnpredicated(op, spec, ins)
	}
	return true, false, fmt.Errorf("arm64 %s operands are outside its complete Go 1.27 BF16 arithmetic forms: %q", op, ins.Raw)
}

func (c *arm64Ctx) lowerARM64SVEBFloatArithmeticPredicated(op Op, spec arm64SVEBFloatArithmeticSpec, ins Instr) (bool, bool, error) {
	second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != 16 || firstBits != 16 || destinationBits != 16 || destination != first {
		return true, false, fmt.Errorf("arm64 %s requires destructive H operands and P0..P7/M: %q", op, ins.Raw)
	}
	firstValue, err := c.loadARM64SVEBFloatVector(first)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, 16)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if spec.scale {
		secondValue, secondType, err := c.loadZRegElements(second, 16)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 8 x bfloat> @llvm.aarch64.sve.fscale.nxv8bf16(%s %s, <vscale x 8 x bfloat> %s, %s %s)\n", result, predicateType, predicateValue, firstValue, secondType, secondValue)
	} else {
		secondValue, err := c.loadARM64SVEBFloatVector(second)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 8 x bfloat> @llvm.aarch64.sve.%s.nxv8bf16(%s %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s)\n", result, spec.intrinsic, predicateType, predicateValue, firstValue, secondValue)
	}
	return true, false, c.storeARM64SVEBFloatVector(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVEBFloatArithmeticUnpredicated(op Op, spec arm64SVEBFloatArithmeticSpec, ins Instr) (bool, bool, error) {
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !firstOK || !destinationOK || firstBits != 16 || destinationBits != 16 {
		return true, false, fmt.Errorf("arm64 %s requires H vector operands: %q", op, ins.Raw)
	}
	firstValue, err := c.loadARM64SVEBFloatVector(first)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0]); secondOK {
		if secondBits != 16 {
			return true, false, fmt.Errorf("arm64 %s requires H vector operands: %q", op, ins.Raw)
		}
		secondValue, err := c.loadARM64SVEBFloatVector(second)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = %s <vscale x 8 x bfloat> %s, %s\n", result, spec.intrinsic, firstValue, secondValue)
	} else {
		second, secondBits, lane, secondOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
		if !spec.indexed || !secondOK || secondBits != 16 || second > 7 || lane > 7 {
			return true, false, fmt.Errorf("arm64 %s indexed source must use Z0..Z7.H[0..7]: %q", op, ins.Raw)
		}
		secondValue, err := c.loadARM64SVEBFloatVector(second)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmul.lane.nxv8bf16(<vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s, i32 %d)\n", result, firstValue, secondValue, lane)
	}
	return true, false, c.storeARM64SVEBFloatVector(destination, "%"+result)
}

func emitARM64SVEBFloatArithmeticDeclarations(b *strings.Builder) {
	for _, intrinsic := range []string{"fadd", "fsub", "fmul", "fmax", "fmaxnm", "fmin", "fminnm"} {
		fmt.Fprintf(b, "declare <vscale x 8 x bfloat> @llvm.aarch64.sve.%s.nxv8bf16(<vscale x 8 x i1>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>)\n", intrinsic)
	}
	b.WriteString("declare <vscale x 8 x bfloat> @llvm.aarch64.sve.fmul.lane.nxv8bf16(<vscale x 8 x bfloat>, <vscale x 8 x bfloat>, i32 immarg)\n")
	b.WriteString("declare <vscale x 8 x bfloat> @llvm.aarch64.sve.fscale.nxv8bf16(<vscale x 8 x i1>, <vscale x 8 x bfloat>, <vscale x 8 x i16>)\n")
}
