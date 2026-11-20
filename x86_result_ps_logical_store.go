package plan9asm

// EXTRACTPS already writes separate logical FP fields through
// storeFPVectorBytes. Its lowering-only result observer must account for those
// same writes, including parameter copies, without treating them as native
// caller stores. The complete scalar span excludes pointers, bools and holes;
// the shared lane effect still requires every selected source byte.
func (c *amd64Ctx) scalarPSLogicalFPWriteTransfer(ins Instr, state *x86ResultState,
	owned []bool, arch string) (bool, bool) {
	form, known, err := x86InsertExtractProperties(ins, arch)
	if !known || err != nil || !form.spec.scalar || form.spec.insert ||
		form.memory < 0 || ins.Args[form.destination].Kind != OpFP {
		return false, false
	}
	if _, err := c.scalarFPSpan(ins.Args[form.destination].FPOffset, 32); err != nil {
		return false, true
	}
	return x86ResultScalarPSLaneStep(ins, form, state, owned, 0, arch, false), true
}
