package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEPredicatePositionIntrinsics = map[Op]string{
	"PFIRSTP": "firstp",
	"PLASTP":  "lastp",
}

func (c *arm64Ctx) lowerARM64SVEPredicatePosition(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, ok := arm64SVEPredicatePositionIntrinsics[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Pn.T, Pg, Xd: %q", op, ins.Raw)
	}
	tested, elementBits, testedOK := arm64ParseSVEPredicateElement(ins.Args[0])
	governing, governingOK := arm64ParseSVEPredicateBare(ins.Args[1], 15)
	if !testedOK || !governingOK || ins.Args[2].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[2].Reg) {
		return true, false, fmt.Errorf("arm64 %s operands do not match its Go 1.27 predicate-position form: %q", op, ins.Raw)
	}
	governingValue, predicateType, err := c.loadPRegElements(governing, elementBits)
	if err != nil {
		return true, false, err
	}
	testedValue, _, err := c.loadPRegElements(tested, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.%s.nxv%di1(%s %s, %s %s)\n", result, intrinsic, lanes, predicateType, governingValue, predicateType, testedValue)
	return true, false, c.storeReg(ins.Args[2].Reg, "%"+result)
}
