package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEDupW(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZDUPW" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm64 ZDUPW expects Rn|RSP, Zd.B|H|S|D without a suffix: %q", ins.Raw)
	}
	source, sourceOK := arm64ParseSVEDupGeneralSource(ins.Args[0])
	destination, elementBits, destinationOK := arm64ParseSVEDupDestination(ins.Args[1], false)
	if !sourceOK || !destinationOK {
		return true, false, fmt.Errorf("arm64 ZDUPW requires R0..R30 or RSP and a B/H/S/D destination: %q", ins.Raw)
	}
	return true, false, c.lowerRawSVEDupGeneral(arm64RawSVEDupGeneral{elementBits: elementBits, source: source, destination: destination})
}
