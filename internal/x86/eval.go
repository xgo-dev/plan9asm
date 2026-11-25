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
		loadKW := "load"
		if c.isVolatileSB(s) {
			loadKW = "load volatile"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i64, ptr %s, align 1\n", t, loadKW, p)
		return "%" + t, nil
	case asm.OpIdent:
		if isX86SystemOrSegIdent(op.Ident) {
			return "0", nil
		}
		return "", fmt.Errorf("amd64: unsupported i64 operand: %s", op.String())
	default:
		return "", fmt.Errorf("amd64: unsupported i64 operand: %s", op.String())
	}
}

func isX86SystemOrSegIdent(ident string) bool {
	s := strings.ToUpper(strings.TrimSpace(ident))
	switch s {
	case "CS", "DS", "ES", "FS", "GS", "SS", "GDTR", "IDTR", "LDTR", "TR", "TASK", "MSW":
		return true
	}
	if len(s) >= 3 && (strings.HasPrefix(s, "CR") || strings.HasPrefix(s, "DR") || strings.HasPrefix(s, "TR")) {
		for i := 2; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func (c *amd64Ctx) isVolatileSB(sym string) bool {
	if len(c.volatileGlobals) == 0 {
		return false
	}
	base, _, ok := asm.ParseSBRef(sym)
	if !ok {
		return false
	}
	base = strings.TrimPrefix(base, "$")
	res := base
	if c.resolve != nil {
		if strings.Contains(base, "·") || strings.Contains(base, "/") || strings.Contains(base, ".") {
			res = c.resolve(base)
		} else {
			res = c.resolve("·" + base)
		}
	}
	return c.volatileGlobals[res]
}

func (c *amd64Ctx) hasSPMem() bool {
	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			for _, arg := range ins.Args {
				if arg.Kind == asm.OpMem && arg.Mem.Base == asm.SP {
					return true
				}
			}
		}
	}
	return false
}

func (c *amd64Ctx) hasOutgoingSPArgs() bool {
	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			for _, arg := range ins.Args {
				if arg.Kind == asm.OpMem && arg.Mem.Base == asm.SP && arg.Mem.Off >= 0 {
					return true
				}
			}
		}
	}
	return false
}
