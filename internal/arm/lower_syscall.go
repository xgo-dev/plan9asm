package arm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *armCtx) zextI32ToI64(v32 string) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v32)
	return "%" + t
}

func (c *armCtx) lowerSyscall(cond string, ins asm.Instr) error {
	if !c.linuxA32 {
		return fmt.Errorf("%w: SWI requires the Linux A32 system call ABI", asm.ErrProbeNeedsContext)
	}
	if op := strings.ToUpper(string(ins.Op)); op != "SWI" && (cond == "" || op != "SWI."+cond) {
		return fmt.Errorf("arm: invalid SWI suffix: %q", ins.Raw)
	}
	if len(ins.Args) > 1 || len(ins.Args) == 1 && (ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "") {
		return fmt.Errorf("arm SWI expects an optional numeric immediate: %q", ins.Raw)
	}
	word := uint32(0xef000000)
	if len(ins.Args) != 0 {
		// Go asm encodes only the low 24 bits of the SWI immediate.
		word |= uint32(ins.Args[0].Imm) & 0x00ffffff
	}
	return c.emitConditionalEffect(cond, func() error {
		// Linux EABI uses r7 for the syscall number and r0-r6 for arguments.
		// Bind both raw return registers. libc syscall loses negative errno and
		// cannot represent the second register or a nonzero SVC immediate.
		var args [8]string
		for i := range args {
			reg := asm.Reg(fmt.Sprintf("R%d", i))
			v, err := c.loadReg(reg)
			if err != nil {
				return err
			}
			args[i] = "i32 " + v
		}
		pair := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call {i32, i32} asm sideeffect \".inst 0x%08x\", \"={r0},={r1},0,1,{r2},{r3},{r4},{r5},{r6},{r7},~{memory},~{cc}\"(%s)\n",
			pair, word, strings.Join(args[:], ", "))
		for i, reg := range []asm.Reg{"R0", "R1"} {
			v := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue {i32, i32} %%%s, %d\n", v, pair, i)
			if err := c.storeReg(reg, "%"+v); err != nil {
				return err
			}
		}
		return nil
	})
}
