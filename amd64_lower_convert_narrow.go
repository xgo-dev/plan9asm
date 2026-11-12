package plan9asm

import "strings"

func (c *amd64Ctx) lowerPackedDoubleToSingle(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if base != "CVTPD2PS" && base != "VCVTPD2PSX" && base != "VCVTPD2PSY" && base != "VCVTPD2PS" {
		return false, false, nil
	}
	return c.lowerPackedPrecisionConvert(op, ins)
}
