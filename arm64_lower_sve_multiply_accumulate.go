package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEMultiplyAccumulateSpec struct {
	intrinsic          string
	predicatedRaw      uint32
	indexedRaw         [3]uint32
	destructiveProduct bool
}

var arm64SVEMultiplyAccumulateSpecs = map[Op]arm64SVEMultiplyAccumulateSpec{
	"ZMLA": {intrinsic: "mla", predicatedRaw: 0x04004000, indexedRaw: [3]uint32{0x44200800, 0x44a00800, 0x44e00800}},
	"ZMLS": {intrinsic: "mls", predicatedRaw: 0x04006000, indexedRaw: [3]uint32{0x44200c00, 0x44a00c00, 0x44e00c00}},
	"ZMAD": {intrinsic: "mad", predicatedRaw: 0x0400c000, destructiveProduct: true},
	"ZMSB": {intrinsic: "msb", predicatedRaw: 0x0400e000, destructiveProduct: true},
}

type arm64SVEMultiplyAccumulateForm struct {
	intrinsic    string
	elementBits  int
	secondSource int
	firstSource  int
	predicate    int
	lane         int
	destination  int
	indexed      bool
}

func arm64SVEMultiplyAccumulateNeedsSVE2(ins Instr) bool {
	return len(ins.Args) == 3
}

func (c *arm64Ctx) lowerARM64SVEMultiplyAccumulate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEMultiplyAccumulateSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || (len(ins.Args) != 3 && len(ins.Args) != 4) {
		return true, false, fmt.Errorf("arm64 %s expects one complete Go 1.27 multiply-accumulate form without a suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) == 3 && spec.indexedRaw[0] == 0 {
		return true, false, fmt.Errorf("arm64 %s requires its predicated four-operand form: %q", op, ins.Raw)
	}
	form := arm64SVEMultiplyAccumulateForm{intrinsic: spec.intrinsic}
	if len(ins.Args) == 4 {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s predicated operands must use one B/H/S/D width and P0..P7.M: %q", op, ins.Raw)
		}
		form.elementBits = secondBits
		form.secondSource = second
		form.firstSource = first
		form.predicate = predicate
		form.destination = destination
	} else {
		multiplier, multiplierBits, lane, multiplierOK := arm64ParseSVEZIndexedElementReg(ins.Args[0])
		multiplicand, multiplicandBits, multiplicandOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !multiplierOK || !multiplicandOK || !destinationOK || multiplierBits != multiplicandBits || multiplicandBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s indexed operands must use one H/S/D width and an encodable lane: %q", op, ins.Raw)
		}
		form.elementBits = multiplierBits
		form.secondSource = multiplier
		form.firstSource = multiplicand
		form.lane = lane
		form.destination = destination
		form.indexed = true
	}
	return true, false, c.lowerARM64SVEMultiplyAccumulateForm(form)
}

func (c *arm64Ctx) lowerARM64SVEMultiplyAccumulateForm(form arm64SVEMultiplyAccumulateForm) error {
	// MLA/MLS accumulate into the old destination. MAD/MSB multiply the
	// old destination and first source, then add/subtract from the second.
	destination, vectorType, err := c.loadZRegElements(form.destination, form.elementBits)
	if err != nil {
		return err
	}
	first, _, err := c.loadZRegElements(form.firstSource, form.elementBits)
	if err != nil {
		return err
	}
	second, _, err := c.loadZRegElements(form.secondSource, form.elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.indexed {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n",
			result, vectorType, form.intrinsic, lanes, form.elementBits, vectorType, destination, vectorType, first, vectorType, second, form.lane)
	} else {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s, %s %s)\n",
			result, vectorType, form.intrinsic, lanes, form.elementBits, predicateType, predicate, vectorType, destination, vectorType, first, vectorType, second)
	}
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
