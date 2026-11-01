package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

type arm64SVEFloatMultiplyForm struct {
	elementBits  int
	first        int
	second       int
	predicate    int
	laneVector   int
	lane         int
	destination  int
	immediate    float64
	hasImmediate bool
	hasLane      bool
	predicated   bool
}

func (c *arm64Ctx) lowerARM64SVEFloatMultiply(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFMUL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || (len(ins.Args) != 3 && len(ins.Args) != 4) {
		return true, false, fmt.Errorf("arm64 ZFMUL expects one complete Go 1.27 floating form without a suffix: %q", ins.Raw)
	}
	form := arm64SVEFloatMultiplyForm{}
	if len(ins.Args) == 4 {
		first, elementBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
		if !firstOK || !predicateOK || !destinationOK || first != destination || elementBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZFMUL predicated form requires matching destructive H/S/D operands and P0..P7.M: %q", ins.Raw)
		}
		form = arm64SVEFloatMultiplyForm{elementBits: elementBits, first: first, predicate: predicate, destination: destination, predicated: true}
		if ins.Args[0].Kind == OpImm {
			if ins.Args[0].ImmRaw != "" || !ins.Args[0].ImmIsFloat {
				return true, false, fmt.Errorf("arm64 ZFMUL immediate requires $(0.5) or $(2.0): %q", ins.Raw)
			}
			form.immediate = math.Float64frombits(uint64(ins.Args[0].Imm))
			constants := arm64SVEFloatArithmeticSpecs[op].constants
			if form.immediate != constants[0] && form.immediate != constants[1] {
				return true, false, fmt.Errorf("arm64 ZFMUL immediate requires $(0.5) or $(2.0): %q", ins.Raw)
			}
			form.hasImmediate = true
		} else {
			second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
			if !secondOK || secondBits != elementBits {
				return true, false, fmt.Errorf("arm64 ZFMUL predicated source must match the destination width: %q", ins.Raw)
			}
			form.second = second
		}
	} else {
		first, elementBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
		if !firstOK || !destinationOK || elementBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZFMUL unpredicated operands must use one H/S/D width: %q", ins.Raw)
		}
		form = arm64SVEFloatMultiplyForm{elementBits: elementBits, first: first, destination: destination}
		if laneVector, laneBits, lane, laneOK := arm64ParseSVEZIndexedElementReg(ins.Args[0]); laneOK {
			if laneBits != elementBits {
				return true, false, fmt.Errorf("arm64 ZFMUL lane width must match the other operands: %q", ins.Raw)
			}
			form.laneVector, form.lane, form.hasLane = laneVector, lane, true
		} else {
			second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
			if !secondOK || secondBits != elementBits {
				return true, false, fmt.Errorf("arm64 ZFMUL vector sources must use one H/S/D width: %q", ins.Raw)
			}
			form.second = second
		}
	}
	return true, false, c.lowerARM64SVEFloatMultiplyForm(form)
}

func (c *arm64Ctx) lowerARM64SVEFloatMultiplyForm(form arm64SVEFloatMultiplyForm) error {
	first, vectorType, err := c.loadRawSVEFloatVector(form.first, form.elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.hasLane {
		laneVector, _, err := c.loadRawSVEFloatVector(form.laneVector, form.elementBits)
		if err != nil {
			return err
		}
		_, _, lanes, _ := arm64SVEFloatType(form.elementBits)
		code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits]
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fmul.lane.nxv%d%s(%s %s, %s %s, i32 %d)\n",
			result, vectorType, lanes, code, vectorType, first, vectorType, laneVector, form.lane)
	} else {
		second := ""
		if form.hasImmediate {
			second, err = c.arm64SVEFloatSplat(form.immediate, form.elementBits)
		} else {
			second, _, err = c.loadRawSVEFloatVector(form.second, form.elementBits)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %s\n", result, vectorType, first, second)
	}
	value := "%" + result
	if form.predicated {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicate, vectorType, value, vectorType, first)
		value = "%" + selected
	}
	return c.storeRawSVEFloatVector(form.destination, form.elementBits, value, vectorType)
}
