package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEComplexMultiplyAccumulateIntrinsics = map[Op]string{
	"ZCMLA":      "cmla",
	"ZSQRDCMLAH": "sqrdcmlah",
}

type arm64SVEComplexMultiplyAccumulateForm struct {
	intrinsic    string
	elementBits  int
	multiplier   int
	multiplicand int
	lane         int
	rotation     int
	destination  int
	indexed      bool
}

func (c *arm64Ctx) lowerARM64SVEComplexMultiplyAccumulate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEComplexMultiplyAccumulateIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 form without a suffix: %q", op, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 %s rotation must be 0, 90, 180, or 270: %q", op, ins.Raw)
	}
	rotation := int(ins.Args[0].Imm)
	if rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270 {
		return true, false, fmt.Errorf("arm64 %s rotation must be 0, 90, 180, or 270: %q", op, ins.Raw)
	}
	form := arm64SVEComplexMultiplyAccumulateForm{intrinsic: intrinsic, rotation: rotation}
	if multiplier, multiplierBits, lane, indexed := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[1]); indexed {
		multiplicand, multiplicandBits, multiplicandOK := arm64ParseSVEZElementReg(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		maximumVector, vectorOK := map[int]int{16: 7, 32: 15}[multiplierBits]
		maximumLane, laneOK := map[int]int{16: 3, 32: 1}[multiplierBits]
		if !multiplicandOK || !destinationOK || !vectorOK || !laneOK || multiplier > maximumVector || lane > maximumLane || multiplierBits != multiplicandBits || multiplicandBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s indexed operands must use an encodable H/S complex lane: %q", op, ins.Raw)
		}
		form.elementBits = multiplierBits
		form.multiplier = multiplier
		form.multiplicand = multiplicand
		form.lane = lane
		form.destination = destination
		form.indexed = true
	} else {
		multiplier, multiplierBits, multiplierOK := arm64ParseSVEZElementReg(ins.Args[1])
		multiplicand, multiplicandBits, multiplicandOK := arm64ParseSVEZElementReg(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !multiplierOK || !multiplicandOK || !destinationOK || multiplierBits != multiplicandBits || multiplicandBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s vector operands must use one B/H/S/D width: %q", op, ins.Raw)
		}
		form.elementBits = multiplierBits
		form.multiplier = multiplier
		form.multiplicand = multiplicand
		form.destination = destination
	}
	return true, false, c.lowerARM64SVEComplexMultiplyAccumulateForm(form)
}

func (c *arm64Ctx) lowerARM64SVEComplexMultiplyAccumulateForm(form arm64SVEComplexMultiplyAccumulateForm) error {
	accumulator, vectorType, err := c.loadZRegElements(form.destination, form.elementBits)
	if err != nil {
		return err
	}
	multiplicand, _, err := c.loadZRegElements(form.multiplicand, form.elementBits)
	if err != nil {
		return err
	}
	multiplier, _, err := c.loadZRegElements(form.multiplier, form.elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.x.nxv%di%d(%s %s, %s %s, %s %s, i32 %d, i32 %d)\n",
			result, vectorType, form.intrinsic, lanes, form.elementBits, vectorType, accumulator, vectorType, multiplicand, vectorType, multiplier, form.lane, form.rotation)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.x.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n",
			result, vectorType, form.intrinsic, lanes, form.elementBits, vectorType, accumulator, vectorType, multiplicand, vectorType, multiplier, form.rotation)
	}
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
