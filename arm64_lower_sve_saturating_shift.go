package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEVariableShiftSpec struct {
	intrinsic string
	immediate bool
	reverse   bool
}

var arm64SVEVariableShiftSpecs = map[Op]arm64SVEVariableShiftSpec{
	"ZSQSHL":   {intrinsic: "sqshl", immediate: true},
	"ZUQSHL":   {intrinsic: "uqshl", immediate: true},
	"ZSQRSHL":  {intrinsic: "sqrshl"},
	"ZSQRSHLR": {intrinsic: "sqrshl", reverse: true},
	"ZSQSHLR":  {intrinsic: "sqshl", reverse: true},
	"ZUQRSHL":  {intrinsic: "uqrshl"},
	"ZUQRSHLR": {intrinsic: "uqrshl", reverse: true},
	"ZUQSHLR":  {intrinsic: "uqshl", reverse: true},
	"ZSRSHL":   {intrinsic: "srshl"},
	"ZSRSHLR":  {intrinsic: "srshl", reverse: true},
	"ZURSHL":   {intrinsic: "urshl"},
	"ZURSHLR":  {intrinsic: "urshl", reverse: true},
}

func (c *arm64Ctx) lowerARM64SVESaturatingShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEVariableShiftSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects shift, Zdn.T, P0..P7.M, Zdn.T without a suffix: %q", op, ins.Raw)
	}
	data, elementBits, dataOK := arm64ParseSVEZElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
	if !dataOK || !predicateOK || !destinationOK || data != destination || elementBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s requires matching destructive data operands and P0..P7.M: %q", op, ins.Raw)
	}
	dataValue, vectorType, err := c.loadZRegElements(data, elementBits)
	if err != nil {
		return true, false, err
	}
	shiftValue := ""
	if ins.Args[0].Kind == OpImm {
		if !spec.immediate || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < 0 || ins.Args[0].Imm >= int64(elementBits) {
			return true, false, fmt.Errorf("arm64 %s immediate must be in 0..%d: %q", op, elementBits-1, ins.Raw)
		}
		shiftValue = fmt.Sprintf("splat (i%d %d)", elementBits, ins.Args[0].Imm)
	} else {
		shifts, shiftBits, shiftsOK := arm64ParseSVEZElementReg(ins.Args[0])
		if !shiftsOK || shiftBits != elementBits {
			return true, false, fmt.Errorf("arm64 %s shift vector must match the B/H/S/D data width: %q", op, ins.Raw)
		}
		shiftValue, _, err = c.loadZRegElements(shifts, elementBits)
		if err != nil {
			return true, false, err
		}
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	firstValue, secondValue := dataValue, shiftValue
	if spec.reverse {
		firstValue, secondValue = shiftValue, dataValue
	}
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n",
		result, vectorType, spec.intrinsic, lanes, elementBits, predicateType, predicateValue, vectorType, firstValue, vectorType, secondValue)
	resultValue := "%" + result
	if spec.reverse {
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicateValue, vectorType, resultValue, vectorType, dataValue)
		resultValue = "%" + selected
	}
	return true, false, c.storeZRegElements(destination, elementBits, resultValue)
}
