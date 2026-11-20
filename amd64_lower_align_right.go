package plan9asm

import "strings"

// Keep both original dispatcher entries on the complete shared grammar.
func (c *amd64Ctx) lowerPackedAlignRight(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if base != "PALIGNR" && base != "VPALIGNR" {
		return false, false, nil
	}
	return c.lowerPackedAlignFamily(op, ins)
}

func amd64UnsignedImmediate(operand Operand, bits int) bool {
	if operand.Kind != OpImm || operand.ImmIsFloat || operand.ImmRaw != "" || bits <= 0 || bits >= 63 {
		return false
	}
	return operand.Imm >= 0 && operand.Imm < int64(uint64(1)<<bits)
}
