package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorSaturatingShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, handled := map[Op]string{"VSQSHL": "sqshl", "VUQSHL": "uqshl"}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects $shift|Vshifts.T, Vvalue.T, Vdst.T with no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for index, operand := range ins.Args[1:] {
		if operand.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s value and destination must be vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(operand.Reg)
		if !valid || !arm64SaturatingShiftArrangement(parsed) {
			return true, false, fmt.Errorf("arm64 %s accepts only B8/B16/H4/H8/S2/S4/D2 arrangements: %q", op, ins.Raw)
		}
		if index == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}

	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	shifts := ""
	switch shiftOperand := ins.Args[0]; shiftOperand.Kind {
	case OpImm:
		if shiftOperand.ImmRaw != "" || shiftOperand.Imm < 0 || shiftOperand.Imm >= int64(arrangement.elementBits) {
			return true, false, fmt.Errorf("arm64 %s immediate shift must be in [0,%d): %q", op, arrangement.elementBits, ins.Raw)
		}
		var constant strings.Builder
		constant.WriteString("<")
		for lane := 0; lane < arrangement.lanes; lane++ {
			if lane != 0 {
				constant.WriteString(", ")
			}
			fmt.Fprintf(&constant, "i%d %d", arrangement.elementBits, shiftOperand.Imm)
		}
		constant.WriteString(">")
		shifts = constant.String()
	case OpReg:
		shiftArrangement, valid := parseARM64VectorArrangement(shiftOperand.Reg)
		if !valid || shiftArrangement != arrangement {
			return true, false, fmt.Errorf("arm64 %s shift-count arrangement must match: %q", op, ins.Raw)
		}
		shifts, err = c.loadARM64VectorInteger(shiftOperand.Reg, arrangement)
		if err != nil {
			return true, false, err
		}
	default:
		return true, false, fmt.Errorf("arm64 %s first operand must be an immediate or vector register: %q", op, ins.Raw)
	}
	value, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di%d(%s %s, %s %s)\n",
		result, vectorType, intrinsic, arrangement.lanes, arrangement.elementBits, vectorType, value, vectorType, shifts)
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, "%"+result)
}

func arm64SaturatingShiftArrangement(arrangement arm64VectorArrangement) bool {
	switch {
	case arrangement.elementBits == 8 && (arrangement.lanes == 8 || arrangement.lanes == 16):
	case arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8):
	case arrangement.elementBits == 32 && (arrangement.lanes == 2 || arrangement.lanes == 4):
	case arrangement.elementBits == 64 && arrangement.lanes == 2:
	default:
		return false
	}
	return true
}
