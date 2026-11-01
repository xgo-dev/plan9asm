package plan9asm

import "fmt"

// lowerARM64VectorShiftLeft implements Go's complete AVSHL immediate optab
// row for all seven accepted 64- and 128-bit vector arrangements.
func (c *arm64Ctx) lowerARM64VectorShiftLeft(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VSHL" {
		return false, false, nil
	}
	form, err := parseARM64VectorShift(op, ins)
	if err != nil {
		return true, false, err
	}
	sourceArrangement, shift := form.arrangement, form.shift
	source, err := c.loadARM64VectorInteger(ins.Args[1].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl <%d x i%d> %s, %s\n", result, sourceArrangement.lanes, sourceArrangement.elementBits, source, arm64VectorIntegerSplat(sourceArrangement, shift))
	return true, false, c.storeARM64VectorInteger(form.destination, sourceArrangement, "%"+result)
}
