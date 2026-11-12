package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEVectorPredicateIncDecSpec struct {
	intrinsic  string
	increment  bool
	saturating bool
}

var arm64SVEVectorPredicateIncDecSpecs = map[Op]arm64SVEVectorPredicateIncDecSpec{
	"ZDECP":   {},
	"ZINCP":   {increment: true},
	"ZSQDECP": {intrinsic: "sqdecp", saturating: true},
	"ZSQINCP": {intrinsic: "sqincp", increment: true, saturating: true},
	"ZUQDECP": {intrinsic: "uqdecp", saturating: true},
	"ZUQINCP": {intrinsic: "uqincp", increment: true, saturating: true},
}

func (c *arm64Ctx) lowerARM64SVEVectorPredicateIncDec(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEVectorPredicateIncDecSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 %s expects Pm.H/S/D, Zdn.H/S/D without a suffix: %q", op, ins.Raw)
	}
	predicate, predicateBits, predicateOK := arm64ParseSVEPredicateElement(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	if !predicateOK || !destinationOK || predicateBits == 8 || predicateBits != destinationBits {
		return true, false, fmt.Errorf("arm64 %s requires matching H/S/D predicate and vector arrangements: %q", op, ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, predicateBits)
	if err != nil {
		return true, false, err
	}
	value, vectorType, err := c.loadZRegElements(destination, destinationBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / destinationBits
	result := c.newTmp()
	if spec.saturating {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n", result, vectorType, spec.intrinsic, lanes, destinationBits, vectorType, value, predicateType, predicateValue)
		return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
	}
	governing, _, err := c.allTruePRegElements(destinationBits)
	if err != nil {
		return true, false, err
	}
	count := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.aarch64.sve.cntp.nxv%di1(%s %s, %s %s)\n", count, lanes, predicateType, governing, predicateType, predicateValue)
	countValue := "%" + count
	if destinationBits != 64 {
		narrowed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrowed, countValue, destinationBits)
		countValue = "%" + narrowed
	}
	inserted := c.newTmp()
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, i%d %s, i64 0\n", inserted, vectorType, destinationBits, countValue)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <vscale x %d x i32> zeroinitializer\n", splat, vectorType, inserted, vectorType, lanes)
	operation := "sub"
	if spec.increment {
		operation = "add"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, operation, vectorType, value, splat)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
