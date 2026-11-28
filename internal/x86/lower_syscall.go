package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func matchesX86Target(goarch, triple string) bool {
	arch, _, _ := strings.Cut(strings.ToLower(triple), "-")
	switch arch {
	case "x86_64", "x86_64h", "amd64":
		return goarch == "amd64"
	case "i386", "i486", "i586", "i686":
		return goarch == "386"
	}
	return false
}

// Match both the source mode and the target machine before emitting native
// instructions. A Linux OS component alone also matches ARM Linux triples.
func syscallTarget(goarch, targetTriple string) (linux, bsd bool) {
	if !matchesX86Target(goarch, targetTriple) {
		return false, false
	}
	parts := strings.Split(strings.ToLower(targetTriple), "-")
	for _, part := range parts[1:] {
		switch strings.TrimRight(part, "0123456789.") {
		case "linux":
			return true, false
		case "darwin", "macos", "macosx", "freebsd", "netbsd", "dragonfly":
			return false, true
		}
	}
	return false, false
}

func (c *amd64Ctx) lowerSyscall(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "INT":
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
			return true, false, fmt.Errorf("x86 INT expects an immediate vector: %q", ins.Raw)
		}
		vector := ins.Args[0].Imm
		if vector == 0x80 && c.goarch == "386" {
			if linux, _ := syscallTarget(c.goarch, c.targetTriple); !linux {
				return true, false, fmt.Errorf("%w: 386 INT $0x80 requires a Linux target triple: %q", asm.ErrProbeNeedsContext, ins.Raw)
			}
			return true, false, c.lowerLinux386Syscall()
		}
		if vector != 3 {
			return true, false, fmt.Errorf("x86: unsupported software interrupt vector %d", vector)
		}
		if !c.isX86TargetTriple() {
			return true, false, fmt.Errorf("%w: INT $3 needs an x86 target", asm.ErrProbeNeedsContext)
		}
		// SIGTRAP handlers and debuggers may resume after INT3.
		c.b.WriteString("  call void asm sideeffect \"int3\", \"~{memory}\"()\n")
		return true, false, nil
	case "SYSCALL":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("amd64 SYSCALL expects no operands: %q", ins.Raw)
		}
		linux, bsd := syscallTarget(c.goarch, c.targetTriple)
		if c.goarch != "amd64" || !linux && !bsd {
			return true, false, fmt.Errorf("%w: raw SYSCALL requires a modeled x86-64 kernel ABI for %q", asm.ErrProbeNeedsContext, c.targetTriple)
		}
		return true, false, c.lowerAMD64Syscall(bsd)
	}
	return false, false, nil
}

func (c *amd64Ctx) lowerAMD64Syscall(bsd bool) error {
	regs := []asm.Reg{asm.AX, asm.DI, asm.SI, asm.DX, asm.Reg("R10"), asm.Reg("R8"), asm.Reg("R9")}
	args := make([]string, len(regs))
	for i, reg := range regs {
		value, err := c.loadReg(reg)
		if err != nil {
			return err
		}
		args[i] = "i64 " + value
	}
	resultType := "{ i64, i64, i64, i64 }"
	instruction := "syscall"
	constraints := "={ax},={dx},={cx},={r11},"
	if bsd {
		resultType = "{ i64, i64, i64, i64, i8 }"
		constraints += "={@ccc},"
	}
	constraints += "0,{di},{si},1,{r10},{r8},{r9}"
	if bsd && c.localStackSlot != "" {
		// BSD/Darwin syscall9 reads arguments 7..9 above the return-address
		// word at the native SP. Keep LLVM's 128-byte red zone untouched and
		// restore SP with LEA so the kernel carry survives.
		sp, err := c.loadReg(asm.SP)
		if err != nil {
			return err
		}
		args = append(args, "i64 "+sp)
		constraints += ",{r12}"
		instruction = "leaq -160(%rsp), %rsp; movq 8(%r12), %r11; movq %r11, 8(%rsp); " +
			"movq 16(%r12), %r11; movq %r11, 16(%rsp); movq 24(%r12), %r11; movq %r11, 24(%rsp); " +
			"syscall; leaq 160(%rsp), %rsp"
	}
	constraints += ",~{dirflag},~{fpsr},~{flags},~{memory}"
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", call, resultType, instruction, constraints, strings.Join(args, ", "))
	for i, reg := range []asm.Reg{asm.AX, asm.DX, asm.CX, "R11"} {
		if i >= 2 && c.regSlot[reg] == "" {
			continue
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, resultType, call, i)
		if err := c.storeReg(reg, "%"+value); err != nil {
			return err
		}
	}
	if bsd {
		byteValue, carry := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 4\n", byteValue, resultType, call)
		fmt.Fprintf(c.b, "  %%%s = trunc i8 %%%s to i1\n", carry, byteValue)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
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
