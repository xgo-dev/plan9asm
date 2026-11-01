package plan9asm

import (
	"fmt"
	"strings"
)

func (c *armCtx) lowerPreload(op, cond string, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "PLD":
	default:
		return false, false, nil
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return true, false, err
	}
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm PLD expects one register-relative memory operand: %q", ins.Raw)
	}
	mem := ins.Args[0].Mem
	if !isARMGeneralReg(mem.Base) || mem.Index != "" || mem.Sym != "" || mem.Off < -4095 || mem.Off > 4095 {
		return true, false, fmt.Errorf("arm PLD operand is absent from Go 1.27's C_SOREG optab row: %q", ins.Raw)
	}
	if cond != "" && !strings.EqualFold(cond, "AL") {
		err := c.emitConditionalEffect(cond, func() error {
			_, _, innerErr := c.lowerPreload(op, "", ins)
			return innerErr
		})
		return true, false, err
	}
	addr, _, _, err := c.addrI32(mem, false)
	if err != nil {
		return true, false, err
	}
	ptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", ptr, addr)
	fmt.Fprintf(c.b, "  call void @llvm.prefetch.p0(ptr %%%s, i32 0, i32 3, i32 1)\n", ptr)
	return true, false, nil
}
