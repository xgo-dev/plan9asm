package plan9asm

import "fmt"

// lowerMoveHighLowPackedSingle implements all forms in Go 1.27's legacy yxr
// and AVX _yvmovhlps tables for the HLPS/LHPS register-only move family.
func (c *amd64Ctx) lowerMoveHighLowPackedSingle(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86MoveHalfProperties(op, ins, c.goarch)
	if !known || !form.spec.registerOnly {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	first, err := c.loadXAsI64x2(ins.Args[form.source].Reg)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadXAsI64x2(ins.Args[form.base].Reg)
	if err != nil {
		return true, false, err
	}
	mask := "<i32 2, i32 0>"
	if form.outputLane == 0 {
		mask = "<i32 1, i32 3>"
	}
	if !form.spec.vector {
		first, second = second, first
		mask = "<i32 0, i32 2>"
		if form.outputLane == 0 {
			mask = "<i32 3, i32 1>"
		}
	}
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x i64> %s, <2 x i64> %s, <2 x i32> %s\n", result, first, second, mask)
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, result)
	if form.spec.vector {
		return true, false, c.storePackedMoveOperand(ins.Args[form.destination], 16, "%"+bytes)
	}
	return true, false, c.storeLegacyXViews(ins.Args[form.destination].Reg, "%"+bytes)
}
