package plan9asm

import "fmt"

func (c *armCtx) zextI32ToI64(v32 string) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v32)
	return "%" + t
}

func (c *armCtx) truncI64ToI32(v64 string) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v64)
	return "%" + t
}

func (c *armCtx) lowerSyscall(op string, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "SWI", "SVC":
		if len(ins.Args) > 1 || (len(ins.Args) == 1 && ins.Args[0].Kind != OpImm) {
			return true, false, fmt.Errorf("arm %s expects optional immediate operand: %q", op, ins.Raw)
		}
		num32 := ""
		if len(ins.Args) == 1 && ins.Args[0].Imm != 0 {
			num32 = c.imm32(ins.Args[0].Imm)
		} else {
			num32, err = c.loadReg(Reg("R7"))
			if err != nil {
				return true, false, err
			}
		}
		loadArg := func(r Reg) (string, error) {
			if _, ok := c.regSlot[r]; !ok {
				return "0", nil
			}
			return c.loadReg(r)
		}
		a1, err := loadArg(Reg("R0"))
		if err != nil {
			return true, false, err
		}
		a2, err := loadArg(Reg("R1"))
		if err != nil {
			return true, false, err
		}
		a3, err := loadArg(Reg("R2"))
		if err != nil {
			return true, false, err
		}
		a4, err := loadArg(Reg("R3"))
		if err != nil {
			return true, false, err
		}
		a5, err := loadArg(Reg("R4"))
		if err != nil {
			return true, false, err
		}
		a6, err := loadArg(Reg("R5"))
		if err != nil {
			return true, false, err
		}
		r := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @syscall(i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s)\n",
			r,
			c.zextI32ToI64(num32),
			c.zextI32ToI64(a1),
			c.zextI32ToI64(a2),
			c.zextI32ToI64(a3),
			c.zextI32ToI64(a4),
			c.zextI32ToI64(a5),
			c.zextI32ToI64(a6),
		)
		if err := c.storeReg(Reg("R0"), c.truncI64ToI32("%"+r)); err != nil {
			return true, false, err
		}
		if _, ok := c.regSlot[Reg("R1")]; ok {
			if err := c.storeReg(Reg("R1"), "0"); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	}
	return false, false, nil
}
