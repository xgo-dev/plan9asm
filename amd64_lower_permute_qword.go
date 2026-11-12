package plan9asm

// Qword permutations reuse the complete typed operand and E4NF read machinery
// with VPERMIL, not its 128-bit selector or variable control/data ordering.
func (c *amd64Ctx) lowerQwordPermute(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86QwordPermuteProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.lowerElementPermute(form, ins)
}
