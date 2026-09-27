package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorSaturatingArithmetic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, handled := map[Op]string{
		"VSQADD": "sadd.sat",
		"VUQADD": "uadd.sat",
		"VSQSUB": "ssub.sat",
		"VUQSUB": "usub.sat",
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || parsed.elementBits == 64 && parsed.lanes != 2 {
			return true, false, fmt.Errorf("arm64 %s accepts only B8/B16/H4/H8/S2/S4/D2 arrangements: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	base, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.v%di%d(%s %s, %s %s)\n",
		result, vectorType, intrinsic, arrangement.lanes, arrangement.elementBits, vectorType, base, vectorType, source)
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, "%"+result)
}
