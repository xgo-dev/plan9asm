package plan9asm

import "fmt"

func (c *armCtx) lowerARMExtendAdd(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects rotated source, dst or rotated source, accumulator, dst: %q", op, ins.Raw)
	}
	sourceOperand := ins.Args[0]
	if sourceOperand.Kind != OpRegShift || sourceOperand.ShiftOp != ShiftRotate || sourceOperand.ShiftReg != "" ||
		!isARMGeneralReg(sourceOperand.Reg) ||
		(sourceOperand.ShiftAmount != 0 && sourceOperand.ShiftAmount != 8 && sourceOperand.ShiftAmount != 16 && sourceOperand.ShiftAmount != 24) {
		return fmt.Errorf("arm %s source must be a general register rotated right by 0, 8, 16, or 24: %q", op, ins.Raw)
	}
	accumulatorOperand := ins.Args[len(ins.Args)-1]
	if len(ins.Args) == 3 {
		accumulatorOperand = ins.Args[1]
	}
	destination := ins.Args[len(ins.Args)-1]
	if accumulatorOperand.Kind != OpReg || !isARMGeneralReg(accumulatorOperand.Reg) ||
		destination.Kind != OpReg || !isARMGeneralReg(destination.Reg) {
		return fmt.Errorf("arm %s accumulator and destination must be general registers: %q", op, ins.Raw)
	}
	rotated, err := c.evalShift(sourceOperand)
	if err != nil {
		return err
	}
	bits := 8
	if op == "XTAH" || op == "XTAHU" {
		bits = 16
	}
	narrowed := c.newTmp()
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i%d\n", narrowed, rotated, bits)
	if op == "XTAB" || op == "XTAH" {
		fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", extended, bits, narrowed)
	} else {
		fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i32\n", extended, bits, narrowed)
	}
	accumulator, err := c.loadReg(accumulatorOperand.Reg)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %s, %%%s\n", result, accumulator, extended)
	return c.selectRegWrite(destination.Reg, cond, "%"+result)
}
