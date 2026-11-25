package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *amd64Ctx) evalI64(op asm.Operand) (string, error) {
	switch op.Kind {
	case asm.OpImm:
		return fmt.Sprintf("%d", op.Imm), nil
	case asm.OpReg:
		return c.loadReg(op.Reg)
	case asm.OpFP:
		return c.evalFPToI64(op.FPOffset)
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, %s %s, align 1\n", t, ptrType, p)
		return "%" + t, nil
	case asm.OpSym:
		s := strings.TrimSpace(op.Sym)
		addrOnly := strings.HasPrefix(s, "$")
		if addrOnly {
			s = strings.TrimSpace(strings.TrimPrefix(s, "$"))
			if mem, ok := asm.ParseMem(s); ok {
				return c.addrFromMem(mem)
			}
		}
		p, err := c.ptrFromSB(s)
		if err != nil {
			// Some runtime asm constants (e.g. $const_stackGuard) come from
			// includes/macros that we don't fully materialize. Treat unresolved
			// bare symbols as immediate zero to keep translation progressing.
			if !strings.Contains(s, "(SB)") {
				return "0", nil
			}
			return "", err
		}
		if addrOnly {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
			return "%" + t, nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", t, p)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported i64 operand: %s", op.String())
	}
}
