package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEDupM(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZDUPM" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return true, false, fmt.Errorf("arm64 ZDUPM expects a resolved logical bitmask immediate and Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	destination, elementBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[1])
	immediate := uint64(ins.Args[0].Imm)
	if !destinationOK || !arm64SVELogicalImmediateRepresentable(elementBits, immediate) {
		return true, false, fmt.Errorf("arm64 ZDUPM immediate is not a Go logical bitmask for the destination width: %q", ins.Raw)
	}
	immediate &= arm64SVEMaskForBits(elementBits)
	value := fmt.Sprintf("splat (i%d %d)", elementBits, immediate)
	return true, false, c.storeZRegElements(destination, elementBits, value)
}
