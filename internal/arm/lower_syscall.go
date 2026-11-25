package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
)

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

func (c *armCtx) lowerSyscall(op string, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "SWI":
		if len(ins.Args) > 1 || (len(ins.Args) == 1 && ins.Args[0].Kind != asm.OpImm) {
			return true, false, fmt.Errorf("arm SWI expects optional immediate operand: %q", ins.Raw)
		}
		num32 := ""
		if len(ins.Args) == 1 && ins.Args[0].Imm != 0 {
			num32 = c.imm32(ins.Args[0].Imm)
		} else {
			num32, err = c.loadReg(asm.Reg("R7"))
			if err != nil {
				return true, false, err
			}
		}
		loadArg := func(r asm.Reg) (string, error) {
			if _, ok := c.regSlot[r]; !ok {
				return "0", nil
			}
			return c.loadReg(r)
		}
		a1, err := loadArg(asm.Reg("R0"))
		if err != nil {
			return true, false, err
		}
		a2, err := loadArg(asm.Reg("R1"))
		if err != nil {
			return true, false, err
		}
		a3, err := loadArg(asm.Reg("R2"))
		if err != nil {
			return true, false, err
		}
		a4, err := loadArg(asm.Reg("R3"))
		if err != nil {
			return true, false, err
		}
		a5, err := loadArg(asm.Reg("R4"))
		if err != nil {
			return true, false, err
		}
		a6, err := loadArg(asm.Reg("R5"))
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
		if err := c.storeReg(asm.Reg("R0"), c.truncI64ToI32("%"+r)); err != nil {
			return true, false, err
		}
		if _, ok := c.regSlot[asm.Reg("R1")]; ok {
			if err := c.storeReg(asm.Reg("R1"), "0"); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	}
	return false, false, nil
}
