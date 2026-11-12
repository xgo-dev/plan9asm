package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEDupQ(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZDUPQ" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 ZDUPQ expects Zn.B|H|S|D[index], Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	source, elementBits, lane, sourceOK := arm64ParseSVEDupElementReg(ins.Args[0])
	destination, destinationBits, destinationOK := arm64ParseSVEDupDestination(ins.Args[1], false)
	if !sourceOK || !destinationOK || elementBits == 128 || elementBits != destinationBits || lane >= 128/elementBits {
		return true, false, fmt.Errorf("arm64 ZDUPQ requires matching B/H/S/D widths and an index within one 128-bit segment: %q", ins.Raw)
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.dupq.lane.nxv%di%d(%s %s, i64 %d)\n", result, vectorType, lanes, elementBits, vectorType, sourceValue, lane)
	return true, false, c.storeZRegElements(destination, elementBits, "%"+result)
}
