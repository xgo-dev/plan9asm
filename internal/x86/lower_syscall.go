package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *amd64Ctx) lowerSyscall(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "INT":
		if c.goarch == "386" && (len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm) {
			return true, false, fmt.Errorf("386 INT expects an immediate vector: %q", ins.Raw)
		}
		if c.goarch == "386" && len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm && ins.Args[0].Imm == 0x80 {
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
		if c.goarch == "amd64" && strings.Contains(strings.ToLower(c.targetTriple), "linux") {
			return true, false, c.lowerLinuxAMD64Syscall()
		}
		num, err := c.loadReg(asm.AX)
		if err != nil {
			return true, false, err
		}
		a1, err := c.loadReg(asm.DI)
		if err != nil {
			return true, false, err
		}
		a2, err := c.loadReg(asm.SI)
		if err != nil {
			return true, false, err
		}
		a3, err := c.loadReg(asm.DX)
		if err != nil {
			return true, false, err
		}
		a4, err := c.loadReg(asm.Reg("R10"))
		if err != nil {
			return true, false, err
		}
		a5, err := c.loadReg(asm.Reg("R8"))
		if err != nil {
			return true, false, err
		}
		a6, err := c.loadReg(asm.Reg("R9"))
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
		if err := c.storeReg(asm.AX, "%"+rax); err != nil {
			return true, false, err
		}
		// Linux raw syscall ABI writes r2 in DX. libc syscall provides only one
		// return value, so keep DX at zero.
		if err := c.storeReg(asm.DX, "0"); err != nil {
			return true, false, err
		}
		return true, false, nil
	}
	return false, false, nil
}

func (c *amd64Ctx) lowerLinuxAMD64Syscall() error {
	regs := []asm.Reg{asm.AX, asm.DI, asm.SI, asm.DX, asm.Reg("R10"), asm.Reg("R8"), asm.Reg("R9")}
	args := make([]string, len(regs))
	for i, reg := range regs {
		value, err := c.loadReg(reg)
		if err != nil {
			return err
		}
		args[i] = value
	}
	call := c.newTmp()
	// Linux x86-64 SYSCALL ABI: inputs in RAX(num), RDI, RSI, RDX, R10, R8, R9;
	// returns r1 in RAX and r2 in RDX; clobbers RCX and R11.
	fmt.Fprintf(c.b, "  %%%s = call { i64, i64 } asm sideeffect %q, %q(i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s)\n",
		call,
		"syscall",
		"={ax},={dx},0,{di},{si},1,{r10},{r8},{r9},~{rcx},~{r11},~{dirflag},~{fpsr},~{flags},~{memory}",
		args[0], args[1], args[2], args[3], args[4], args[5], args[6],
	)
	for i, reg := range []asm.Reg{asm.AX, asm.DX} {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i64 } %%%s, %d\n", value, call, i)
		if err := c.storeReg(reg, "%"+value); err != nil {
			return err
		}
	}
	return nil
}

func (c *amd64Ctx) lowerLinux386Syscall() error {
	regs := []asm.Reg{asm.AX, asm.BX, asm.CX, asm.DX, asm.SI, asm.DI, asm.BP}
	args := make([]string, len(regs))
	for i, reg := range regs {
		value, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: reg}, asm.I32)
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
	for i, reg := range []asm.Reg{asm.AX, asm.DX} {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", value, call, i)
		if err := c.storeRegSized(reg, asm.I32, "%"+value); err != nil {
			return err
		}
	}
	return nil
}

func (c *amd64Ctx) emitX86Trap() {
	c.b.WriteString("  call void asm sideeffect \"int3\", \"~{memory}\"()\n")
	c.b.WriteString("  unreachable\n")
}
