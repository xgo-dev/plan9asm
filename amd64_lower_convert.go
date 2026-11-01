package plan9asm

import (
	"strconv"
	"strings"
)

func amd64ParseMReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "M") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "M"))
	if err != nil || n < 0 || n > 7 {
		return 0, false
	}
	return n, true
}

// Legacy named entries use the complete shared typed/native family.
func (c *amd64Ctx) lowerPackedFloatToDword(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedNumericConversion(op, ins)
}

func (c *amd64Ctx) lowerPackedSingleToDouble(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if base != "CVTPS2PD" && base != "VCVTPS2PD" {
		return false, false, nil
	}
	return c.lowerPackedPrecisionConvert(op, ins)
}
