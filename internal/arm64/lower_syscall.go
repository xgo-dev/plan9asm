package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// SVC uses the kernel register ABI. A C library wrapper changes the error
// convention and cannot return both x0 and x1.
func (c *arm64Ctx) lowerSyscall(op asm.Op, ins asm.Instr) (bool, bool, error) {
	if op != "SVC" {
		return false, false, nil
	}
	imm := int64(0)
	if len(ins.Args) > 0 {
		a := ins.Args[0]
		if len(ins.Args) != 1 || a.Kind != asm.OpImm || a.ImmRaw != "" || a.Imm < 0 || a.Imm > 65535 {
			return true, false, fmt.Errorf("arm64 SVC expects optional imm16: %q", ins.Raw)
		}
		imm = a.Imm
	}
	num, last, carry := 8, 5, false
	switch {
	case !c.nativeAArch64:
		return true, false, fmt.Errorf("%w: SVC requires a native AArch64 kernel ABI", asm.ErrProbeNeedsContext)
	case strings.Contains(c.targetTriple, "-linux"):
	case strings.Contains(c.targetTriple, "-darwin"), strings.Contains(c.targetTriple, "-macos"), strings.Contains(c.targetTriple, "-ios"):
		if imm != 128 {
			return true, false, fmt.Errorf("arm64: unsupported Darwin SVC immediate %d", imm)
		}
		num, last, carry = 16, 8, true
	case strings.Contains(c.targetTriple, "-freebsd"), strings.Contains(c.targetTriple, "-openbsd"):
		last, carry = 7, true
	case strings.Contains(c.targetTriple, "-netbsd"):
		num, last, carry = 17, 7, true
	default:
		return true, false, fmt.Errorf("%w: unknown SVC ABI for %s", asm.ErrProbeNeedsContext, c.targetTriple)
	}

	tpl := fmt.Sprintf("svc #%d", imm)
	resultTy := "{ i64, i64 }"
	constraints := []string{"={x0}", "={x1}"}
	if carry {
		resultTy = "{ i64, i64, i64 }"
		tpl += "\\0A\\09cset $2, cs"
		constraints = append(constraints, "=r")
	}
	var args []string
	addInput := func(reg int, constraint string) error {
		v, err := c.loadReg(asm.Reg(fmt.Sprintf("R%d", reg)))
		if err != nil {
			return err
		}
		args = append(args, "i64 "+v)
		constraints = append(constraints, constraint)
		return nil
	}
	for reg := 0; reg <= last; reg++ {
		con := fmt.Sprintf("{x%d}", reg)
		if reg < 2 {
			con = fmt.Sprint(reg)
		}
		if err := addInput(reg, con); err != nil {
			return true, false, err
		}
	}
	if err := addInput(num, fmt.Sprintf("{x%d}", num)); err != nil {
		return true, false, err
	}
	constraints = append(constraints, "~{cc}", "~{memory}")
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect \"%s\", \"%s\"(%s)\n", out, resultTy, tpl, strings.Join(constraints, ","), strings.Join(args, ", "))
	for i, r := range []asm.Reg{"R0", "R1"} {
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", v, resultTy, out, i)
		if err := c.storeReg(r, "%"+v); err != nil {
			return true, false, err
		}
	}
	if carry {
		v, bit := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 2\n  %%%s = trunc i64 %%%s to i1\n", v, resultTy, out, bit, v)
		c.storeFlag(c.flagsCSlot, "%"+bit)
		if c.flagFlow != nil {
			c.flagFlow.clobbers = true
		}
		c.flagsDefined = flagC
	}
	return true, false, nil
}
