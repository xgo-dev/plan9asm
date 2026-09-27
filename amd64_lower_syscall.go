package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerSyscall(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "LRET":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("x86 LRET expects no operands: %q", ins.Raw)
		}
		// The raw decoder uses the Go spelling LRET for the 64-bit far return
		// byte sequence. LLVM's x86 assembler names the same instruction LRETQ.
		c.b.WriteString("  call void asm sideeffect \"lretq\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	case "WAIT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("x86 WAIT expects no operands: %q", ins.Raw)
		}
		c.b.WriteString("  call void asm sideeffect \"wait\", \"~{memory}\"()\n")
		return true, false, nil
	case "HLT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("x86 HLT expects no operands: %q", ins.Raw)
		}
		c.b.WriteString("  call void asm sideeffect \"hlt\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	case "UD2":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("x86 UD2 expects no operands: %q", ins.Raw)
		}
		c.b.WriteString("  call void asm sideeffect \"ud2\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	case "INT":
		if c.goarch == "386" && (len(ins.Args) != 1 || ins.Args[0].Kind != OpImm) {
			return true, false, fmt.Errorf("386 INT expects an immediate vector: %q", ins.Raw)
		}
		if c.goarch == "386" && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].Imm == 0x80 {
			if !strings.Contains(strings.ToLower(c.targetTriple), "linux") {
				return true, false, fmt.Errorf("386 INT $0x80 requires a Linux target triple: %q", ins.Raw)
			}
			return true, false, c.lowerLinux386Syscall()
		}
		// Software interrupt/trap path (e.g. runtime.exitThread INT $3).
		if c.goarch == "386" {
			c.emitX86Trap()
		} else {
			// Preserve the established amd64 lowering. The 386 path needs an
			// actual trap because Windows uses INT $3 as an executable stub.
			c.b.WriteString("  unreachable\n")
		}
		return true, true, nil
	case "SYSCALL":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("amd64 SYSCALL expects no operands: %q", ins.Raw)
		}
		num, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		a1, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		a2, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		a3, err := c.loadReg(DX)
		if err != nil {
			return true, false, err
		}
		a4, err := c.loadReg(Reg("R10"))
		if err != nil {
			return true, false, err
		}
		a5, err := c.loadReg(Reg("R8"))
		if err != nil {
			return true, false, err
		}
		a6, err := c.loadReg(Reg("R9"))
		if err != nil {
			return true, false, err
		}

		r := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @syscall(i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s)\n", r, num, a1, a2, a3, a4, a5, a6)
		isErr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, -1\n", isErr, r)
		errno32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @cliteErrno()\n", errno32)
		errno64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", errno64, errno32)
		negErr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 0, %%%s\n", negErr, errno64)
		rax := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %%%s\n", rax, isErr, negErr, r)
		if err := c.storeReg(AX, "%"+rax); err != nil {
			return true, false, err
		}
		// Linux raw syscall ABI writes r2 in DX. libc syscall provides only one
		// return value, so keep DX at zero.
		if err := c.storeReg(DX, "0"); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}

func (c *amd64Ctx) lowerLinux386Syscall() error {
	regs := []Reg{AX, BX, CX, DX, SI, DI, BP}
	args := make([]string, len(regs))
	for i, reg := range regs {
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: reg}, I32)
		if err != nil {
			return err
		}
		args[i] = value
	}
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect %q, %q(i32 %s, i32 %s, i32 %s, i32 %s, i32 %s, i32 %s, i32 %s)\n",
		call,
		"int $$0x80",
		"={ax},={dx},{ax},{bx},{cx},{dx},{si},{di},{bp},~{dirflag},~{fpsr},~{flags},~{memory}",
		args[0], args[1], args[2], args[3], args[4], args[5], args[6],
	)
	for i, reg := range []Reg{AX, DX} {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", value, call, i)
		if err := c.storeRegSized(reg, I32, "%"+value); err != nil {
			return err
		}
	}
	return nil
}

func (c *amd64Ctx) emitX86Trap() {
	c.b.WriteString("  call void asm sideeffect \"int3\", \"~{memory}\"()\n")
	c.b.WriteString("  unreachable\n")
}
