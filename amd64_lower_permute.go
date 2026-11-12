package plan9asm

// Dword variable permutations share the complete full-vector data/index
// envelope and E4NF reads with qword variable permutations.
func (c *amd64Ctx) lowerVariableDwordPermute(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86VariableDwordPermuteProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.lowerElementPermute(form, ins)
}
