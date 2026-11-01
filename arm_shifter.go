package plan9asm

import "fmt"

// Go asm5 types 3 and 23 use the ARM shifter operand, but oplook canonicalizes
// every textual immediate-zero right shift to LSL #0 (issue 64715). Register
// amounts use their low byte and saturate, except ROR. Neither rule is a raw
// LLVM shift. Explicit SRL/SRA $0 are also canonicalized; $32 is not, so its
// masked imm5 zero still means #32.
func validateARMShifter(source Operand) error {
	if source.Kind != OpRegShift || !isARMGeneralReg(source.Reg) {
		return fmt.Errorf("ARM shifter requires a general register: %s", source.String())
	}
	switch source.ShiftOp {
	case ShiftLeft, ShiftRight, ShiftArith, ShiftRotate:
	default:
		return fmt.Errorf("ARM shifter has invalid operation: %s", source.String())
	}
	if source.ShiftReg != "" {
		if !isARMGeneralReg(source.ShiftReg) {
			return fmt.Errorf("ARM shifter count requires a general register: %s", source.String())
		}
	} else if source.ShiftAmount < 0 || source.ShiftAmount > 31 {
		return fmt.Errorf("ARM shifter immediate must fit Go's imm5 grammar: %s", source.String())
	}
	return nil
}

func (c *armCtx) evalARMShifter(source Operand) (result, carry string, err error) {
	if err := validateARMShifter(source); err != nil {
		return "", "", err
	}
	value, err := c.loadReg(source.Reg)
	if err != nil {
		return "", "", err
	}
	op := map[ShiftOp]string{ShiftLeft: "SLL", ShiftRight: "SRL", ShiftArith: "SRA", ShiftRotate: "ROR"}[source.ShiftOp]
	if source.ShiftReg == "" {
		if source.ShiftAmount == 0 {
			return value, c.loadFlagValue(c.flagsCSlot), nil
		}
		result, carry = c.emitARMImmediateShift(op, value, uint32(source.ShiftAmount))
	} else {
		amount, loadErr := c.loadReg(source.ShiftReg)
		if loadErr != nil {
			return "", "", loadErr
		}
		result, carry = c.emitARMRegisterShift(op, value, amount)
	}
	return result, carry, nil
}

// Capture the shifter carry before writing an aliased destination. Re-reading
// the shifted register afterwards would silently use the new register value.
func (c *armCtx) evalARMLogicalOperand(op string, source Operand) (value, carry string, err error) {
	if source.Kind == OpRegShift {
		return c.evalARMShifter(source)
	}
	value, err = c.eval32(source, false)
	return value, armLogicalImmediateCarry(op, source), err
}

func (c *armCtx) emitARMRotate(value, amount string) string {
	tmp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %s)\n", tmp, value, value, amount)
	return "%" + tmp
}

func armShifterDefinesCarry(source Operand) bool {
	return source.Kind == OpRegShift && source.ShiftReg == "" && source.ShiftAmount != 0
}

func validateARMDataProcessing(op string, ins Instr, setFlags bool) error {
	for _, suffix := range armInstructionSuffixes(ins) {
		if suffix != "" && suffix != "S" && !armCondCodes[suffix] {
			return fmt.Errorf("ARM %s data-processing suffix is outside Go asm5: %s", op, ins.Raw)
		}
	}
	wantMin, wantMax := 2, 3
	if op == "MOVW" || op == "MVN" || op == "TST" || op == "TEQ" || op == "CMP" || op == "CMN" {
		wantMax = 2
	}
	if len(ins.Args) < wantMin || len(ins.Args) > wantMax {
		return fmt.Errorf("ARM %s data-processing operand count is outside Go asm5: %s", op, ins.Raw)
	}
	source := ins.Args[0]
	if source.Kind != OpImm && !(source.Kind == OpReg && isARMGeneralReg(source.Reg)) && source.Kind != OpRegShift {
		return fmt.Errorf("ARM %s data-processing source must be an immediate/register/shifter: %s", op, ins.Raw)
	}
	if source.Kind == OpRegShift {
		if err := validateARMShifter(source); err != nil {
			return err
		}
	}
	for _, operand := range ins.Args[1:] {
		if operand.Kind != OpReg || !isARMGeneralReg(operand.Reg) {
			return fmt.Errorf("ARM %s data-processing input/destination must be a general register: %s", op, ins.Raw)
		}
	}
	if (op == "MOVW" || op == "MVN") && setFlags && source.Kind == OpImm {
		return fmt.Errorf("ARM %s immediate .S is absent from Go asm5: %s", op, ins.Raw)
	}
	if op == "CMP" || op == "CMN" || op == "TST" || op == "TEQ" {
		return armRequireConditionOnlySuffix(ins)
	}
	return nil
}
