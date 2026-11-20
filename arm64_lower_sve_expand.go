package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEExpand(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZEXPAND" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZEXPAND expects Zn.B|H|S|D, Pg, Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || !predicateOK || !destinationOK || sourceBits != destinationBits {
		return true, false, fmt.Errorf("arm64 ZEXPAND requires matching B/H/S/D vectors and a bare P0..P7 predicate: %q", ins.Raw)
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, sourceBits)
	if err != nil {
		return true, false, err
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / sourceBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.expand.nxv%di%d(%s %s, %s %s)\n", result, vectorType, lanes, sourceBits, predicateType, predicateValue, vectorType, sourceValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
