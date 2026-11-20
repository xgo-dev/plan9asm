package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEFloatPredicatedPairwiseSpec struct {
	intrinsic string
	sve2      bool
	faminmax  bool
}

var arm64SVEFloatPredicatedPairwiseSpecs = map[Op]arm64SVEFloatPredicatedPairwiseSpec{
	"ZFABD":  {intrinsic: "fabd"},
	"ZFADDP": {intrinsic: "faddp", sve2: true},
	"ZFAMAX": {intrinsic: "famax", sve2: true, faminmax: true},
	"ZFAMIN": {intrinsic: "famin", sve2: true, faminmax: true},
}

func (c *arm64Ctx) lowerARM64SVEFloatPredicatedPairwise(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEFloatPredicatedPairwiseSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects Zm.H|S|D, Zdn.H|S|D, Pg/M, Zdn.H|S|D without a suffix: %q", op, ins.Raw)
	}
	second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[1])
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
	repeatedDestination, repeatedBits, repeatedOK := arm64SVEFloatElementReg(ins.Args[3])
	if !secondOK || !destinationOK || !predicateOK || !repeatedOK || secondBits != destinationBits || repeatedBits != destinationBits || repeatedDestination != destination {
		return true, false, fmt.Errorf("arm64 %s requires matching destructive H/S/D operands and P0..P7/M: %q", op, ins.Raw)
	}
	destinationValue, vectorType, err := c.loadRawSVEFloatVector(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	secondValue, _, err := c.loadRawSVEFloatVector(second, secondBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, destinationBits)
	if err != nil {
		return true, false, err
	}
	_, _, lanes, err := arm64SVEFloatType(destinationBits)
	if err != nil {
		return true, false, err
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[destinationBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%d%s(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, mangle, predicateType, predicateValue, vectorType, destinationValue, vectorType, secondValue)
	return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, vectorType)
}
