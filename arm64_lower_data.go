package plan9asm

import (
	"fmt"
)

func (c *arm64Ctx) lowerData(op Op, postInc bool, ins Instr) (ok bool, terminated bool, err error) {
	if err := arm64ScalarMoveOperandClassError(op, ins); err != nil {
		return true, false, err
	}
	if ok, terminated, err := c.lowerARM64RegisterAddress(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64ScalarMemory(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64ScalarMemoryWriteback(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64SymbolScalarMove(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64ScalarExtend(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerARM64IntegerPair(op, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "MOVK", "MOVKW", "MOVN", "MOVNW", "MOVZ", "MOVZW":
		return true, false, c.lowerARM64MoveWide(op, ins)

	case "MOVD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 MOVD expects 2 operands: %q", ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		if src.Kind == OpReg && dst.Kind == OpReg &&
			(isARM64GeneralOrZeroReg(src.Reg) || src.Reg == SP || src.Reg == "RSP") &&
			(isARM64GeneralOrZeroReg(dst.Reg) || dst.Reg == SP || dst.Reg == "RSP") {
			return true, false, c.lowerMachineRegisterCopy(src.Reg, dst.Reg)
		}
		v, err := c.eval64(src, postInc)
		if err != nil {
			return true, false, err
		}
		switch dst.Kind {
		case OpReg:
			return true, false, c.storeReg(dst.Reg, v)
		case OpMem:
			return true, false, c.storeMem(dst.Mem, 64, postInc, v)
		case OpFP:
			return true, false, c.storeFPResult64(dst.FPOffset, v)
		default:
			return true, false, nil
		}

	case "MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU":
		bits := 8
		if op == "MOVH" || op == "MOVHU" {
			bits = 16
		} else if op == "MOVW" || op == "MOVWU" {
			bits = 32
		}
		signed := op == "MOVB" || op == "MOVH" || op == "MOVW"
		return true, false, c.lowerNarrowMove(op, ins, bits, signed, postInc)

	case "MOVBW", "MOVHW":
		bits := 8
		if op == "MOVHW" {
			bits = 16
		}
		return true, false, c.lowerSignedNarrowLoadToWord(op, ins, bits, postInc)
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerARM64MoveWide(op Op, ins Instr) error {
	form, handled, err := parseARM64NamedMoveWide(op, ins)
	if err != nil {
		return err
	}
	if !handled {
		return fmt.Errorf("arm64: unknown move-wide operation %s", op)
	}
	return c.lowerRawMoveWide(form)
}

func (c *arm64Ctx) lowerSignedNarrowLoadToWord(op Op, ins Instr, bits int, postInc bool) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return fmt.Errorf("arm64 %s expects memory, C_ZREG: %q", op, ins.Raw)
	}
	value, err := c.loadMem(ins.Args[0].Mem, bits, postInc)
	if err != nil {
		return err
	}
	narrow := c.newTmp()
	signed := c.newTmp()
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, value, bits)
	fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", signed, bits, narrow)
	fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, signed)
	return c.storeReg(ins.Args[1].Reg, "%"+wide)
}

func (c *arm64Ctx) lowerNarrowMove(op Op, ins Instr, bits int, signed, postInc bool) error {
	if handled, _, err := c.lowerARM64SymbolScalarMove(op, ins); handled {
		return err
	}
	if len(ins.Args) != 2 {
		return fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
	}
	src, dst := ins.Args[0], ins.Args[1]
	var value string
	var err error
	switch src.Kind {
	case OpMem:
		value, err = c.loadMem(src.Mem, bits, postInc)
	case OpReg:
		value, err = c.loadRegisterWidth(src.Reg, bits)
	default:
		value, err = c.eval64(src, false)
	}
	if err != nil {
		return err
	}

	switch dst.Kind {
	case OpReg:
		// A MOVW immediate is materialized through the 32-bit register view,
		// which clears the upper half even though register and memory sources
		// for MOVW are sign-extended.
		value = c.arm64ExtendNarrow(value, bits, signed && src.Kind != OpImm)
		return c.storeReg(dst.Reg, value)
	case OpMem:
		return c.storeMem(dst.Mem, bits, postInc, value)
	case OpFP:
		value = c.arm64ExtendNarrow(value, bits, signed)
		return c.storeFPResult64(dst.FPOffset, value)
	default:
		return fmt.Errorf("arm64 %s unsupported destination: %q", op, ins.Raw)
	}
}

func (c *arm64Ctx) arm64ExtendNarrow(value string, bits int, signed bool) string {
	narrow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, value, bits)
	extended := c.newTmp()
	extendOp := "zext"
	if signed {
		extendOp = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s i%d %%%s to i64\n", extended, extendOp, bits, narrow)
	return "%" + extended
}
