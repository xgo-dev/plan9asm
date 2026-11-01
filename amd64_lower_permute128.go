package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerPermute128(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86Permute128Properties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	// Type6 has no selector-based fault suppression: even two zero halves
	// and dead results retain the complete unaligned m256 native access.
	first, err := c.loadX86PackedShiftBytes(ins.Args[form.first], 32, true)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadPackedCompareBytes(ins.Args[form.second], 32)
	if err != nil {
		return true, false, err
	}
	a, b, selected := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", a, first)
	fmt.Fprintf(c.b, "  %%%s = bitcast <32 x i8> %s to <4 x i64>\n", b, second)
	var indices []int
	var zeros []string
	hasZero := false
	for lane := 0; lane < 4; lane++ {
		at := form.sourceByte(lane * 8)
		zero := at < 0
		if zero {
			at = 0 // A constant select below does not observe this lane.
		}
		indices = append(indices, at/8)
		zeros = append(zeros, fmt.Sprint("i1 ", zero))
		hasZero = hasZero || zero
	}
	fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i64> %%%s, <4 x i64> %%%s, <4 x i32> %s\n",
		selected, a, b, llvmI32Mask(indices))
	if hasZero {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <4 x i1> <%s>, <4 x i64> zeroinitializer, <4 x i64> %%%s\n",
			value, strings.Join(zeros, ", "), selected)
		selected = value
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i64> %%%s to <32 x i8>\n", out, selected)
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], 32, "%"+out)
}
