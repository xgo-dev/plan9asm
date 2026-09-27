package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorAddLongAcross(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic := ""
	switch op {
	case "VSADDLV":
		intrinsic = "saddlv"
	case "VUADDLV":
		intrinsic = "uaddlv"
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects an arranged vector source and bare V destination: %q", op, ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[0].Reg)
	if !valid || !((arrangement.elementBits == 8 && (arrangement.lanes == 8 || arrangement.lanes == 16)) ||
		(arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8)) ||
		(arrangement.elementBits == 32 && arrangement.lanes == 4)) {
		return true, false, fmt.Errorf("arm64 %s accepts only B8, B16, H4, H8, or S4 source: %q", op, ins.Raw)
	}
	if strings.Contains(string(ins.Args[1].Reg), ".") {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}
	if _, valid := arm64ParseVReg(ins.Args[1].Reg); !valid {
		return true, false, fmt.Errorf("arm64 %s destination must be a bare V register: %q", op, ins.Raw)
	}

	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	resultBits := arrangement.elementBits * 2
	intrinsicResultBits := resultBits
	if intrinsicResultBits < 32 {
		// LLVM 22 cannot legalize an i16 result from the AArch64 across-lane
		// intrinsic. The instruction writes an H register, but the intrinsic
		// must return i32; only its low 16 bits are architecturally defined.
		intrinsicResultBits = 32
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.aarch64.neon.%s.i%d.v%di%d(<%d x i%d> %s)\n",
		result, intrinsicResultBits, intrinsic, intrinsicResultBits, arrangement.lanes, arrangement.elementBits,
		arrangement.lanes, arrangement.elementBits, source)
	resultValue := "%" + result
	if intrinsicResultBits != resultBits {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i%d %s to i%d\n",
			truncated, intrinsicResultBits, resultValue, resultBits)
		resultValue = "%" + truncated
	}
	return true, false, c.storeARM64ScalarToVReg(ins.Args[1].Reg, resultBits, resultValue)
}
