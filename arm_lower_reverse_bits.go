package plan9asm

import "fmt"

func (c *armCtx) lowerARMReverseBits(op, cond string, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || !isARMGeneralReg(ins.Args[0].Reg) ||
		ins.Args[1].Kind != OpReg || !isARMGeneralReg(ins.Args[1].Reg) {
		return fmt.Errorf("arm %s expects two general registers: %q", op, ins.Raw)
	}
	source, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	result := ""
	switch op {
	case "REV":
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bswap.i32(i32 %s)\n", reversed, source)
		result = "%" + reversed
	case "RBIT":
		reversed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bitreverse.i32(i32 %s)\n", reversed, source)
		result = "%" + reversed
	case "REV16":
		low := c.newTmp()
		high := c.newTmp()
		lowShifted := c.newTmp()
		highShifted := c.newTmp()
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, 16711935\n", low, source)
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, -16711936\n", high, source)
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, 8\n", lowShifted, low)
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, 8\n", highShifted, high)
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", combined, lowShifted, highShifted)
		result = "%" + combined
	case "REVSH":
		narrowed := c.newTmp()
		reversed := c.newTmp()
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", narrowed, source)
		fmt.Fprintf(c.b, "  %%%s = call i16 @llvm.bswap.i16(i16 %%%s)\n", reversed, narrowed)
		fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i32\n", extended, reversed)
		result = "%" + extended
	default:
		return fmt.Errorf("arm: unsupported reverse instruction %s", op)
	}
	return c.selectRegWrite(ins.Args[1].Reg, cond, result)
}
