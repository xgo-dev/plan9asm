package plan9asm

import "fmt"

type armSaturationSpec struct {
	intrinsic string
	minWidth  int64
	maxWidth  int64
	shifted   bool
}

var armSaturationSpecs = map[string]armSaturationSpec{
	"SSAT":   {intrinsic: "ssat", minWidth: 1, maxWidth: 32, shifted: true},
	"USAT":   {intrinsic: "usat", minWidth: 0, maxWidth: 31, shifted: true},
	"SSAT16": {intrinsic: "ssat16", minWidth: 1, maxWidth: 16},
	"USAT16": {intrinsic: "usat16", minWidth: 0, maxWidth: 15},
}

func armSaturationRegister(reg Reg) bool {
	return isARMGeneralReg(reg) && reg != PC && reg != Reg("R15")
}

func (c *armCtx) lowerSaturation(op, condition string, ins Instr) (bool, bool, error) {
	spec, ok := armSaturationSpecs[op]
	if !ok {
		return false, false, nil
	}
	if len(ins.Args) != 3 || ins.Args[1].Kind != OpImm || ins.Args[1].ImmRaw != "" ||
		ins.Args[2].Kind != OpReg || !armSaturationRegister(ins.Args[2].Reg) {
		return true, false, fmt.Errorf("arm %s expects register or shifted register, saturation width, destination register: %q", op, ins.Raw)
	}
	width := ins.Args[1].Imm
	if width < spec.minWidth || width > spec.maxWidth {
		return true, false, fmt.Errorf("arm %s saturation width %d is outside [%d, %d]: %q", op, width, spec.minWidth, spec.maxWidth, ins.Raw)
	}
	source := ins.Args[0]
	switch source.Kind {
	case OpReg:
		if !armSaturationRegister(source.Reg) {
			return true, false, fmt.Errorf("arm %s source must be R0-R14: %q", op, ins.Raw)
		}
	case OpRegShift:
		if !spec.shifted || !armSaturationRegister(source.Reg) || source.ShiftReg != "" {
			return true, false, fmt.Errorf("arm %s does not accept this source shift: %q", op, ins.Raw)
		}
		switch source.ShiftOp {
		case ShiftLeft:
			if source.ShiftAmount < 0 || source.ShiftAmount > 31 {
				return true, false, fmt.Errorf("arm %s LSL amount is outside [0, 31]: %q", op, ins.Raw)
			}
		case ShiftArith:
			if source.ShiftAmount < 1 || source.ShiftAmount > 32 {
				return true, false, fmt.Errorf("arm %s ASR amount is outside [1, 32]: %q", op, ins.Raw)
			}
		default:
			return true, false, fmt.Errorf("arm %s supports only LSL and ASR source shifts: %q", op, ins.Raw)
		}
	default:
		return true, false, fmt.Errorf("arm %s source must be a general register: %q", op, ins.Raw)
	}

	err := c.emitConditionalEffect(condition, func() error {
		value, err := c.loadReg(source.Reg)
		if err != nil {
			return err
		}
		if source.Kind == OpRegShift && source.ShiftAmount != 0 {
			amount := source.ShiftAmount
			operation := "shl"
			if source.ShiftOp == ShiftArith {
				operation = "ashr"
				if amount == 32 {
					amount = 31
				}
			}
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %d\n", shifted, operation, value, amount)
			value = "%" + shifted
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.arm.%s(i32 %s, i32 %d)\n", result, spec.intrinsic, value, width)
		return c.storeReg(ins.Args[2].Reg, "%"+result)
	})
	return true, false, err
}
