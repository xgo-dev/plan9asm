package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64VectorShiftLeft implements Go's complete AVSHL immediate optab
// row for all seven accepted 64- and 128-bit vector arrangements.
func (c *arm64Ctx) lowerARM64VectorShiftLeft(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VSHL" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "VSHL" || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 VSHL expects $shift, Vsrc.<T>, Vdst.<T> with no suffix: %q", ins.Raw)
	}
	sourceArrangement, sourceValid := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationValid := parseARM64VectorArrangement(ins.Args[2].Reg)
	if !sourceValid || !destinationValid || sourceArrangement != destinationArrangement || !arm64VDUPArrangementAllowed(sourceArrangement) {
		return true, false, fmt.Errorf("arm64 VSHL requires matching B8/B16/H4/H8/S2/S4/D2 arrangements: %q", ins.Raw)
	}
	shift := ins.Args[0].Imm
	if shift < 0 || shift >= int64(sourceArrangement.elementBits) {
		return true, false, fmt.Errorf("arm64 VSHL shift must be in [0,%d]: %q", sourceArrangement.elementBits-1, ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[1].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl <%d x i%d> %s, %s\n", result, sourceArrangement.lanes, sourceArrangement.elementBits, source, arm64VectorIntegerSplat(sourceArrangement, shift))
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, sourceArrangement, "%"+result)
}
