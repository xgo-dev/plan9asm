package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *amd64Ctx) lowerCmpBt(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "CMPB", "CMPW", "CMPL", "CMPQ":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 CMPQ expects 2 operands: %q", ins.Raw)
		}
		ty := asm.I64
		switch op {
		case "CMPB":
			ty = asm.I8
		case "CMPW":
			ty = asm.I16
		case "CMPL":
			ty = asm.I32
		case "CMPQ":
			ty = asm.I64
		}
		a, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		b, err := c.evalIntSized(ins.Args[1], ty)
		if err != nil {
			return true, false, err
		}
		c.setCmpFlagsSized(ty, a, b)
		return true, false, nil

	case "TESTB", "TESTW", "TESTL", "TESTQ":
		// TEST* a,b sets flags based on (a & b) without storing the result.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects 2 operands: %q", op, ins.Raw)
		}
		ty := asm.I64
		switch op {
		case "TESTB":
			ty = asm.I8
		case "TESTW":
			ty = asm.I16
		case "TESTL":
			ty = asm.I32
		case "TESTQ":
			ty = asm.I64
		}
		a, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		b, err := c.evalIntSized(ins.Args[1], ty)
		if err != nil {
			return true, false, err
		}
		c.setTestFlagsSized(ty, a, b)
		return true, false, nil

	case "BTQ", "BTSQ", "BTRQ":
		spec, _ := x86ExtraScalarTable.Lookup(op)
		return true, false, c.lowerX86ExtraBit(spec, ins)
	}
	return false, false, nil
}

func (c *amd64Ctx) setCmpFlagsSized(ty asm.LLVMType, a, b string) {
	// Unlike most Plan 9 x86 instructions, CMP spells its operands in
	// comparison order: CMP a,b sets architectural flags for a - b.
	diff := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", diff, ty, a, b)
	c.setSubFlagsSized(ty, a, b, "%"+diff)
}

func (c *amd64Ctx) setTestFlagsSized(ty asm.LLVMType, a, b string) {
	// TEST sets CF=0, OF=0, and ZF/SF/PF from (a & b).
	and := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", and, ty, a, b)
	c.setLogicFlagsSized(ty, "%"+and)
}

func (c *amd64Ctx) evalIntSized(op asm.Operand, ty asm.LLVMType) (string, error) {
	switch op.Kind {
	case asm.OpImm:
		// LLVM will interpret the literal in the destination integer width.
		return fmt.Sprintf("%d", op.Imm), nil
	case asm.OpReg:
		v64, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		if ty == asm.I64 {
			return v64, nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	case asm.OpFP:
		v64, err := c.evalFPToI64(op.FPOffset)
		if err != nil {
			return "", err
		}
		if ty == asm.I64 {
			return v64, nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", t, ty, ptrType, p)
		return "%" + t, nil
	case asm.OpSym:
		s := strings.TrimSpace(op.Sym)
		if strings.HasPrefix(s, "$") {
			address := strings.TrimSpace(strings.TrimPrefix(s, "$"))
			if strings.HasSuffix(address, "(SB)") {
				p, err := c.ptrFromSB(address)
				if err != nil {
					return "", err
				}
				wide := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", wide, p)
				if ty == asm.I64 {
					return "%" + wide, nil
				}
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", value, wide, ty)
				return "%" + value, nil
			}
			return "", fmt.Errorf("%w: unresolved x86 immediate %s", asm.ErrProbeNeedsContext, s)
		}
		if strings.HasSuffix(s, "(SB)") {
			p, err := c.ptrFromSB(s)
			if err != nil {
				return "", err
			}
			t := c.newTmp()
			loadKW := "load"
			if c.isVolatileSB(s) {
				loadKW = "load volatile"
			}
			fmt.Fprintf(c.b, "  %%%s = %s %s, ptr %s, align 1\n", t, loadKW, ty, p)
			return "%" + t, nil
		}
		if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
			address, ok := asm.ParseImmExpr(s)
			if !ok {
				return "", fmt.Errorf("%w: unresolved x86 address %s", asm.ErrProbeNeedsContext, s)
			}
			v := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load volatile %s, ptr inttoptr (i64 %d to ptr), align 1\n", v, ty, address)
			return "%" + v, nil
		}
		return "", fmt.Errorf("amd64: unsupported sym int operand: %s", op.String())
	case asm.OpIdent:
		if isX86SystemOrSegIdent(op.Ident) {
			return "", fmt.Errorf("amd64: unsupported system/segment register operand %s (hardware descriptor/control/segment register reads are not modeled)", op.Ident)
		}
		return "", fmt.Errorf("amd64: unsupported int operand: %s", op.String())
	default:
		return "", fmt.Errorf("amd64: unsupported int operand: %s", op.String())
	}
}
