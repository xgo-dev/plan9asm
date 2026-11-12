package plan9asm

import "fmt"

func (c *arm64Ctx) lowerSyscall(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "SVC":
		form, err := parseARM64SyscallForm(c.targetTriple, ins)
		if err != nil {
			return true, false, err
		}
		input, borrowed := c.nanosleepInputAt([2]int{c.currentBlock, c.currentInstruction})
		if c.nanosleepInput != nil && (!borrowed || input.form != form) {
			return true, false, fmt.Errorf("%w: changed Linux nanosleep input/emission", ErrProbeNeedsContext)
		}
		num, err := c.loadReg(form.number)
		if err != nil {
			return true, false, err
		}
		loadArg := func(r Reg) (string, error) {
			if borrowed && r != "R0" && r != "R1" {
				return "0", nil // these registers are not nanosleep operand roles
			}
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
		c.emitARM64SyscallIR(form, "  %%%s = call i64 @syscall(i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s)\n", r, num, a1, a2, a3, a4, a5, a6)
		isErr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, -1\n", isErr, r)
		errno32 := c.newTmp()
		c.emitARM64SyscallIR(form, "  %%%s = call i32 @cliteErrno()\n", errno32)
		errno64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", errno64, errno32)

		if form.os == arm64SyscallDarwinCarry {
			// Darwin syscall asm checks carry flag (BCC) after SVC:
			// - C=0 success, R0=r1
			// - C=1 error,   R0=errno
			r0 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %%%s\n", r0, isErr, errno64, r)
			if err := c.storeReg(Reg("R0"), "%"+r0); err != nil {
				return true, false, err
			}
			c.recordMachineUnavailable("R1")
			c.invalidateARM64Flags(form.flagsUnavailable)
			c.storeFlag(c.flagsCSlot, "%"+isErr)
			return true, false, nil
		}

		// Linux's normal return writes R0 only. Other GP and existing NZCV
		// values remain intact; SVC never supplies an uninitialized flag.
		negErr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 0, %%%s\n", negErr, errno64)
		r0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %%%s\n", r0, isErr, negErr, r)
		if err := c.storeReg(Reg("R0"), "%"+r0); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}
