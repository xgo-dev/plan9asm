package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEPredicateIterateSpec struct {
	intrinsic string
	byteOnly  bool
}

var arm64SVEPredicateIterateSpecs = map[Op]arm64SVEPredicateIterateSpec{
	"PPFIRST": {intrinsic: "pfirst", byteOnly: true},
	"PPNEXT":  {intrinsic: "pnext"},
}

func (c *arm64Ctx) lowerARM64SVEPredicateIterate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPredicateIterateSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Pdn.T, Pg, Pdn.T: %q", op, ins.Raw)
	}
	current, currentBits, currentOK := arm64ParseSVEPredicateElement(ins.Args[0])
	governing, governingOK := arm64ParseSVEPredicateBare(ins.Args[1], 15)
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[2])
	if !currentOK || !governingOK || !destinationOK || current != destination || currentBits != destinationBits || (spec.byteOnly && currentBits != 8) {
		return true, false, fmt.Errorf("arm64 %s operands do not match its Go 1.27 read-modify-write predicate form: %q", op, ins.Raw)
	}
	governingValue, predicateType, err := c.loadPRegElements(governing, currentBits)
	if err != nil {
		return true, false, err
	}
	currentValue, _, err := c.loadPRegElements(current, currentBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / currentBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di1(%s %s, %s %s)\n", result, predicateType, spec.intrinsic, lanes, predicateType, governingValue, predicateType, currentValue)
	if err := c.storePRegElements(destination, currentBits, "%"+result); err != nil {
		return true, false, err
	}
	c.setSVEPredicateFlags(governingValue, "%"+result, predicateType, lanes)
	return true, false, nil
}
