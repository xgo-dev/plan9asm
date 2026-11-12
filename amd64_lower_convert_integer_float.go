package plan9asm

import (
	"fmt"
	"strings"
)

// lowerLegacyIntegerToFloat implements Go 1.27's complete legacy integer to
// floating-point conversion group: yxcvlf/yxcvqf scalar conversions and the
// two yxcvm2 packed conversions.
func (c *amd64Ctx) lowerLegacyIntegerToFloat(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if _, known, _ := x86SignedPackedFloatProperties(ins, c.goarch); known {
		return c.lowerSignedPackedIntegerFloat(op, ins)
	}
	rawOp := strings.ToUpper(string(op))
	if strings.Contains(rawOp, ".") {
		base := strings.SplitN(rawOp, ".", 2)[0]
		switch base {
		case "CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "CVTPL2PS", "CVTPL2PD":
			return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", base, ins.Raw)
		}
	}
	switch rawOp {
	case "CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD":
		return c.lowerLegacyScalarIntegerToFloat(rawOp, ins)
	case "CVTPL2PS", "CVTPL2PD":
		return c.lowerLegacyPackedIntegerToFloat(rawOp, ins)
	default:
		return false, false, nil
	}
}

func (c *amd64Ctx) lowerLegacyScalarIntegerToFloat(op string, ins Instr) (bool, bool, error) {
	return c.lowerSignedIntegerScalarFloat(Op(op), ins)
}

func (c *amd64Ctx) lowerLegacyPackedIntegerToFloat(op string, ins Instr) (bool, bool, error) {
	return c.lowerSignedPackedIntegerFloat(Op(op), ins)
}
