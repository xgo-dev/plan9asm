package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEFloatMultiplyAccumulateSpec struct {
	intrinsic string
	indexed   bool
}

var arm64SVEFloatMultiplyAccumulateSpecs = map[Op]arm64SVEFloatMultiplyAccumulateSpec{
	"ZFMLA":  {intrinsic: "fmla", indexed: true},
	"ZFMLS":  {intrinsic: "fmls", indexed: true},
	"ZFMAD":  {intrinsic: "fmad"},
	"ZFMSB":  {intrinsic: "fmsb"},
	"ZFNMLA": {intrinsic: "fnmla"},
	"ZFNMLS": {intrinsic: "fnmls"},
	"ZFNMAD": {intrinsic: "fnmad"},
	"ZFNMSB": {intrinsic: "fnmsb"},
}

type arm64SVEFloatMultiplyAccumulateForm struct {
	intrinsic    string
	elementBits  int
	multiplier   int
	multiplicand int
	predicate    int
	lane         int
	destination  int
	indexed      bool
}

func (c *arm64Ctx) lowerARM64SVEFloatMultiplyAccumulate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEFloatMultiplyAccumulateSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 && (len(ins.Args) != 3 || !spec.indexed) {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 floating multiply-accumulate form without a suffix: %q", op, ins.Raw)
	}
	form := arm64SVEFloatMultiplyAccumulateForm{intrinsic: spec.intrinsic}
	if len(ins.Args) == 4 {
		multiplier, multiplierBits, multiplierOK := arm64SVEFloatElementReg(ins.Args[0])
		multiplicand, multiplicandBits, multiplicandOK := arm64SVEFloatElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
		if !multiplierOK || !multiplicandOK || !predicateOK || !destinationOK || multiplierBits != multiplicandBits || multiplicandBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s predicated operands must use one H/S/D width and P0..P7.M: %q", op, ins.Raw)
		}
		form.elementBits = multiplierBits
		form.multiplier = multiplier
		form.multiplicand = multiplicand
		form.predicate = predicate
		form.destination = destination
	} else {
		multiplier, multiplierBits, lane, multiplierOK := arm64ParseSVEZIndexedElementReg(ins.Args[0])
		multiplicand, multiplicandBits, multiplicandOK := arm64SVEFloatElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
		if !multiplierOK || !multiplicandOK || !destinationOK || multiplierBits != multiplicandBits || multiplicandBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s indexed operands must use one H/S/D width and an encodable lane: %q", op, ins.Raw)
		}
		form.elementBits = multiplierBits
		form.multiplier = multiplier
		form.multiplicand = multiplicand
		form.lane = lane
		form.destination = destination
		form.indexed = true
	}
	return true, false, c.lowerARM64SVEFloatMultiplyAccumulateForm(form)
}

func (c *arm64Ctx) lowerARM64SVEFloatMultiplyAccumulateForm(form arm64SVEFloatMultiplyAccumulateForm) error {
	accumulator, vectorType, err := c.loadRawSVEFloatVector(form.destination, form.elementBits)
	if err != nil {
		return err
	}
	multiplicand, _, err := c.loadRawSVEFloatVector(form.multiplicand, form.elementBits)
	if err != nil {
		return err
	}
	multiplier, _, err := c.loadRawSVEFloatVector(form.multiplier, form.elementBits)
	if err != nil {
		return err
	}
	_, _, lanes, _ := arm64SVEFloatType(form.elementBits)
	code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits]
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%d%s(%s %s, %s %s, %s %s, i32 %d)\n",
			result, vectorType, form.intrinsic, lanes, code, vectorType, accumulator, vectorType, multiplicand, vectorType, multiplier, form.lane)
	} else {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s, %s %s, %s %s)\n",
			result, vectorType, form.intrinsic, lanes, code, predicateType, predicate, vectorType, accumulator, vectorType, multiplicand, vectorType, multiplier)
	}
	return c.storeRawSVEFloatVector(form.destination, form.elementBits, "%"+result, vectorType)
}
