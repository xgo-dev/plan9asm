package plan9asm

import "fmt"

func (c *armCtx) lowerARMBitfield(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return fmt.Errorf("arm %s expects width, lsb, dst or width, lsb, src, dst: %q", op, ins.Raw)
	}
	if op == "BFC" && len(ins.Args) != 3 {
		return fmt.Errorf("arm BFC expects width, lsb, dst: %q", ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" ||
		ins.Args[1].Kind != OpImm || ins.Args[1].ImmRaw != "" {
		return fmt.Errorf("arm %s width and lsb must be resolved integer constants: %q", op, ins.Raw)
	}
	width, lsb := ins.Args[0].Imm, ins.Args[1].Imm
	if width <= 0 || width > 32 || lsb < 0 || lsb >= 32 || width+lsb > 32 {
		return fmt.Errorf("arm %s requires 1 <= width <= 32 and 0 <= lsb with width+lsb <= 32: %q", op, ins.Raw)
	}
	sourceOperand := ins.Args[len(ins.Args)-1]
	if len(ins.Args) == 4 {
		sourceOperand = ins.Args[2]
	}
	destination := ins.Args[len(ins.Args)-1]
	if sourceOperand.Kind != OpReg || !isARMGeneralReg(sourceOperand.Reg) ||
		destination.Kind != OpReg || !isARMGeneralReg(destination.Reg) {
		return fmt.Errorf("arm %s source and destination must be general registers: %q", op, ins.Raw)
	}
	source, err := c.loadReg(sourceOperand.Reg)
	if err != nil {
		return err
	}
	fieldMask := ^uint32(0)
	if width < 32 {
		fieldMask = uint32(1)<<uint(width) - 1
	}
	placedMask := fieldMask << uint(lsb)
	result := ""
	switch op {
	case "BFX", "BFXU":
		shifted := c.newTmp()
		if op == "BFX" {
			left := 32 - width - lsb
			fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %d\n", shifted, source, left)
			extended := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %%%s, %d\n", extended, shifted, 32-width)
			result = "%" + extended
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", shifted, source, lsb)
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %d\n", masked, shifted, int32(fieldMask))
			result = "%" + masked
		}
	case "BFC":
		cleared := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", cleared, source, int32(^placedMask))
		result = "%" + cleared
	case "BFI":
		old, loadErr := c.loadReg(destination.Reg)
		if loadErr != nil {
			return loadErr
		}
		cleared := c.newTmp()
		masked := c.newTmp()
		shifted := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", cleared, old, int32(^placedMask))
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %d\n", masked, source, int32(fieldMask))
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %d\n", shifted, masked, lsb)
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", combined, cleared, shifted)
		result = "%" + combined
	default:
		return fmt.Errorf("arm: unsupported bitfield instruction %s", op)
	}
	return c.selectRegWrite(destination.Reg, cond, result)
}
