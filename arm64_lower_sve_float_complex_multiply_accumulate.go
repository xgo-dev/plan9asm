package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEFloatComplexMultiplyAccumulateForm struct {
	elementBits  int
	multiplier   int
	multiplicand int
	predicate    int
	lane         int
	rotation     int
	destination  int
	indexed      bool
}

func (c *arm64Ctx) lowerARM64SVEFloatComplexMultiplyAccumulate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFCMLA" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || (len(ins.Args) != 4 && len(ins.Args) != 5) {
		return true, false, fmt.Errorf("arm64 ZFCMLA expects one complete Go 1.27 form without a suffix: %q", ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 ZFCMLA rotation must be 0, 90, 180, or 270: %q", ins.Raw)
	}
	rotation := int(ins.Args[0].Imm)
	if rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270 {
		return true, false, fmt.Errorf("arm64 ZFCMLA rotation must be 0, 90, 180, or 270: %q", ins.Raw)
	}
	form := arm64SVEFloatComplexMultiplyAccumulateForm{rotation: rotation}
	if len(ins.Args) == 5 {
		multiplier, multiplierBits, multiplierOK := arm64SVEFloatElementReg(ins.Args[1])
		multiplicand, multiplicandBits, multiplicandOK := arm64SVEFloatElementReg(ins.Args[2])
		predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[3], "M", 7)
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[4])
		if !multiplierOK || !multiplicandOK || !predicateOK || !destinationOK || multiplierBits != multiplicandBits || multiplicandBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZFCMLA predicated operands must use one H/S/D width and P0..P7.M: %q", ins.Raw)
		}
		form.elementBits = multiplierBits
		form.multiplier = multiplier
		form.multiplicand = multiplicand
		form.predicate = predicate
		form.destination = destination
	} else {
		multiplier, multiplierBits, lane, multiplierOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[1])
		multiplicand, multiplicandBits, multiplicandOK := arm64SVEFloatElementReg(ins.Args[2])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
		maximumVector, vectorOK := map[int]int{16: 7, 32: 15}[multiplierBits]
		maximumLane, laneOK := map[int]int{16: 3, 32: 1}[multiplierBits]
		if !multiplierOK || !multiplicandOK || !destinationOK || !vectorOK || !laneOK || multiplier > maximumVector || lane > maximumLane || multiplierBits != multiplicandBits || multiplicandBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZFCMLA indexed operands must use an encodable H/S complex lane: %q", ins.Raw)
		}
		form.elementBits = multiplierBits
		form.multiplier = multiplier
		form.multiplicand = multiplicand
		form.lane = lane
		form.destination = destination
		form.indexed = true
	}
	return true, false, c.lowerARM64SVEFloatComplexMultiplyAccumulateForm(form)
}

func (c *arm64Ctx) lowerARM64SVEFloatComplexMultiplyAccumulateForm(form arm64SVEFloatComplexMultiplyAccumulateForm) error {
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
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fcmla.lane.nxv%d%s(%s %s, %s %s, %s %s, i32 %d, i32 %d)\n",
			result, vectorType, lanes, code, vectorType, accumulator, vectorType, multiplicand, vectorType, multiplier, form.lane, form.rotation)
	} else {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fcmla.nxv%d%s(%s %s, %s %s, %s %s, %s %s, i32 %d)\n",
			result, vectorType, lanes, code, predicateType, predicate, vectorType, accumulator, vectorType, multiplicand, vectorType, multiplier, form.rotation)
	}
	return c.storeRawSVEFloatVector(form.destination, form.elementBits, "%"+result, vectorType)
}
