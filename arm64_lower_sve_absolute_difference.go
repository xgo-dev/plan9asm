package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEAbsoluteDifferenceKind uint8

const (
	arm64SVEAbsoluteAccumulate arm64SVEAbsoluteDifferenceKind = iota
	arm64SVEAbsoluteDifference
	arm64SVEAbsoluteLongAccumulate
	arm64SVEAbsoluteLongDifference
	arm64SVEAbsolutePairAccumulate
)

type arm64SVEAbsoluteDifferenceSpec struct {
	intrinsic string
	kind      arm64SVEAbsoluteDifferenceKind
}

var arm64SVEAbsoluteDifferenceSpecs = map[Op]arm64SVEAbsoluteDifferenceSpec{
	"ZSABA":   {intrinsic: "saba", kind: arm64SVEAbsoluteAccumulate},
	"ZUABA":   {intrinsic: "uaba", kind: arm64SVEAbsoluteAccumulate},
	"ZSABD":   {intrinsic: "sabd", kind: arm64SVEAbsoluteDifference},
	"ZUABD":   {intrinsic: "uabd", kind: arm64SVEAbsoluteDifference},
	"ZSABALB": {intrinsic: "sabalb", kind: arm64SVEAbsoluteLongAccumulate},
	"ZSABALT": {intrinsic: "sabalt", kind: arm64SVEAbsoluteLongAccumulate},
	"ZUABALB": {intrinsic: "uabalb", kind: arm64SVEAbsoluteLongAccumulate},
	"ZUABALT": {intrinsic: "uabalt", kind: arm64SVEAbsoluteLongAccumulate},
	"ZSABDLB": {intrinsic: "sabdlb", kind: arm64SVEAbsoluteLongDifference},
	"ZSABDLT": {intrinsic: "sabdlt", kind: arm64SVEAbsoluteLongDifference},
	"ZUABDLB": {intrinsic: "uabdlb", kind: arm64SVEAbsoluteLongDifference},
	"ZUABDLT": {intrinsic: "uabdlt", kind: arm64SVEAbsoluteLongDifference},
	"ZSADALP": {intrinsic: "sadalp", kind: arm64SVEAbsolutePairAccumulate},
	"ZUADALP": {intrinsic: "uadalp", kind: arm64SVEAbsolutePairAccumulate},
}

type arm64SVEAbsoluteDifferenceForm struct {
	elementBits int
	sourceBits  int
	first       int
	second      int
	predicate   int
	destination int
}

func (c *arm64Ctx) lowerARM64SVEAbsoluteDifference(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEAbsoluteDifferenceSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	form, err := arm64ParseSVEAbsoluteDifferenceForm(op, spec, ins)
	if err != nil {
		return true, false, err
	}
	return true, false, c.lowerARM64SVEAbsoluteDifferenceForm(spec, form)
}

func arm64ParseSVEAbsoluteDifferenceForm(op Op, spec arm64SVEAbsoluteDifferenceSpec, ins Instr) (arm64SVEAbsoluteDifferenceForm, error) {
	form := arm64SVEAbsoluteDifferenceForm{}
	switch spec.kind {
	case arm64SVEAbsoluteDifference:
		if len(ins.Args) != 4 {
			return form, fmt.Errorf("arm64 %s expects Zm.T, Zdn.T, Pg/M, Zdn.T: %q", op, ins.Raw)
		}
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits || first != destination {
			return form, fmt.Errorf("arm64 %s requires matching-width destructive data and P0..P7/M: %q", op, ins.Raw)
		}
		return arm64SVEAbsoluteDifferenceForm{elementBits: firstBits, first: first, second: second, predicate: predicate, destination: destination}, nil
	case arm64SVEAbsolutePairAccumulate:
		if len(ins.Args) != 3 {
			return form, fmt.Errorf("arm64 %s expects Zn.Tb, Pg/M, Zda.T: %q", op, ins.Raw)
		}
		first, sourceBits, firstOK := arm64ParseSVEZElementReg(ins.Args[0])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !firstOK || !predicateOK || !destinationOK || sourceBits == 64 || destinationBits != 2*sourceBits {
			return form, fmt.Errorf("arm64 %s requires a B/H/S source, P0..P7/M, and H/S/D accumulator: %q", op, ins.Raw)
		}
		return arm64SVEAbsoluteDifferenceForm{elementBits: destinationBits, sourceBits: sourceBits, first: first, predicate: predicate, destination: destination}, nil
	default:
		if len(ins.Args) != 3 {
			return form, fmt.Errorf("arm64 %s expects three scalable vector operands: %q", op, ins.Raw)
		}
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
		if !secondOK || !firstOK || !destinationOK || secondBits != firstBits {
			return form, fmt.Errorf("arm64 %s requires matching source widths: %q", op, ins.Raw)
		}
		if spec.kind == arm64SVEAbsoluteAccumulate {
			if firstBits != destinationBits {
				return form, fmt.Errorf("arm64 %s requires matching B/H/S/D sources and accumulator: %q", op, ins.Raw)
			}
			return arm64SVEAbsoluteDifferenceForm{elementBits: firstBits, first: first, second: second, destination: destination}, nil
		}
		if firstBits == 64 || destinationBits != 2*firstBits {
			return form, fmt.Errorf("arm64 %s requires B/H/S sources widened to H/S/D: %q", op, ins.Raw)
		}
		return arm64SVEAbsoluteDifferenceForm{elementBits: destinationBits, sourceBits: firstBits, first: first, second: second, destination: destination}, nil
	}
}

func (c *arm64Ctx) lowerARM64SVEAbsoluteDifferenceForm(spec arm64SVEAbsoluteDifferenceSpec, form arm64SVEAbsoluteDifferenceForm) error {
	if spec.kind == arm64SVEAbsoluteDifference {
		first, vectorType, err := c.loadZRegElements(form.first, form.elementBits)
		if err != nil {
			return err
		}
		second, _, err := c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		lanes := 128 / form.elementBits
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, form.elementBits, predicateType, predicate, vectorType, first, vectorType, second)
		return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
	}
	if spec.kind == arm64SVEAbsoluteAccumulate {
		accumulator, vectorType, err := c.loadZRegElements(form.destination, form.elementBits)
		if err != nil {
			return err
		}
		first, _, err := c.loadZRegElements(form.first, form.elementBits)
		if err != nil {
			return err
		}
		second, _, err := c.loadZRegElements(form.second, form.elementBits)
		if err != nil {
			return err
		}
		lanes := 128 / form.elementBits
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, form.elementBits, vectorType, accumulator, vectorType, first, vectorType, second)
		return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
	}
	sourceType, _, err := arm64SVEVectorType(form.sourceBits)
	if err != nil {
		return err
	}
	destinationType, destinationLanes, err := arm64SVEVectorType(form.elementBits)
	if err != nil {
		return err
	}
	first, _, err := c.loadZRegElements(form.first, form.sourceBits)
	if err != nil {
		return err
	}
	accumulator := ""
	if spec.kind == arm64SVEAbsoluteLongAccumulate || spec.kind == arm64SVEAbsolutePairAccumulate {
		accumulator, _, err = c.loadZRegElements(form.destination, form.elementBits)
		if err != nil {
			return err
		}
	}
	result := c.newTmp()
	switch spec.kind {
	case arm64SVEAbsoluteLongAccumulate:
		second, _, err := c.loadZRegElements(form.second, form.sourceBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, destinationType, spec.intrinsic, destinationLanes, form.elementBits, destinationType, accumulator, sourceType, first, sourceType, second)
	case arm64SVEAbsoluteLongDifference:
		second, _, err := c.loadZRegElements(form.second, form.sourceBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, destinationType, spec.intrinsic, destinationLanes, form.elementBits, sourceType, first, sourceType, second)
	case arm64SVEAbsolutePairAccumulate:
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n", result, destinationType, spec.intrinsic, destinationLanes, form.elementBits, predicateType, predicate, destinationType, accumulator, sourceType, first)
	default:
		return fmt.Errorf("unknown ARM64 SVE absolute-difference kind %d", spec.kind)
	}
	return c.storeZRegElements(form.destination, form.elementBits, "%"+result)
}
