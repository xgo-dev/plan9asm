package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) evalI64(op Operand) (string, error) {
	if c.goReadOnlyOperand.allows(op, 8) {
		return c.evalIntSized(op, I64)
	}
	if err := unresolvedSymbolicImmediateErrorForArch(op, ArchAMD64); err != nil {
		return "", err
	}
	switch op.Kind {
	case OpImm:
		return fmt.Sprintf("%d", op.Imm), nil
	case OpReg:
		return c.loadReg(op.Reg)
	case OpFP:
		return c.evalFPToI64(op.FPOffset)
	case OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, %s %s, align 1\n", t, ptrType, p)
		return "%" + t, nil
	case OpSym:
		s := strings.TrimSpace(op.Sym)
		addrOnly := strings.HasPrefix(s, "$")
		if addrOnly {
			s = strings.TrimSpace(strings.TrimPrefix(s, "$"))
			if mem, matched, err := parseX86SymbolIndexedMemory(s); matched {
				if err != nil {
					return "", err
				}
				return c.addrFromSymbolIndexedAddress(mem)
			}
			if mem, ok := parseMem(s); ok {
				return c.addrFromMem(mem)
			}
		}
		p, err := c.ptrFromSB(s)
		if err != nil {
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
