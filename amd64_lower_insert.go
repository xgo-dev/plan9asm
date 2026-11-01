package plan9asm

// lowerPackedVectorInsert implements every Go 1.27 form in _yvinsertf128,
// _yvinsertf32x4, and _yvinsertf32x8. The floating and integer spellings have
// identical bit-level insert behavior; their lane type only changes EVEX mask
// granularity.
func (c *amd64Ctx) lowerPackedVectorInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerInsertExtractFamily(op, ins)
}
