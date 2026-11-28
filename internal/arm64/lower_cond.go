package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *arm64Ctx) lowerCond(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "CSEL", "CSELW", "CSINC", "CSINCW", "CSINV", "CSINVW", "CSNEG", "CSNEGW":
		if len(ins.Args) != 4 || ins.Args[3].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects cond, a, b, dstReg: %q", op, ins.Raw)
		}
		cond, ok := arm64ConditionOperand(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s expects a condition operand: %q", op, ins.Raw)
		}
		word := strings.HasSuffix(string(op), "W")
		a, err := c.loadCondOperand(ins.Args[1], word)
		if err != nil {
			return true, false, err
		}
		bv, err := c.loadCondOperand(ins.Args[2], word)
		if err != nil {
			return true, false, err
		}
		typeName := "i64"
		if word {
			typeName = "i32"
		}
		switch {
		case strings.HasPrefix(string(op), "CSINC"):
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %s, 1\n", t, typeName, bv)
			bv = "%" + t
		case strings.HasPrefix(string(op), "CSINV"):
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", t, typeName, bv)
			bv = "%" + t
		case strings.HasPrefix(string(op), "CSNEG"):
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", t, typeName, bv)
			bv = "%" + t
		}
		cv, err := c.condValue(cond)
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", out, cv, typeName, a, typeName, bv)
		return true, false, c.storeCondResult(ins.Args[3].Reg, "%"+out, word)

	case "CSET", "CSETW", "CSETM", "CSETMW":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects cond, dstReg: %q", op, ins.Raw)
		}
		cond, ok := arm64ConditionOperand(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s expects a condition operand: %q", op, ins.Raw)
		}
		cv, err := c.condValue(cond)
		if err != nil {
			return true, false, err
		}
		word := strings.HasSuffix(string(op), "W")
		typeName := "i64"
		if word {
			typeName = "i32"
		}
		trueValue := "1"
		if strings.HasPrefix(string(op), "CSETM") {
			trueValue = "-1"
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s 0\n", out, cv, typeName, trueValue, typeName)
		return true, false, c.storeCondResult(ins.Args[1].Reg, "%"+out, word)

	case "CINC", "CINCW", "CINV", "CINVW", "CNEG", "CNEGW":
		if len(ins.Args) != 3 || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects cond, srcReg, dstReg: %q", op, ins.Raw)
		}
		cond, ok := arm64ConditionOperand(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s expects a condition operand: %q", op, ins.Raw)
		}
		word := strings.HasSuffix(string(op), "W")
		src, err := c.loadCondOperand(ins.Args[1], word)
		if err != nil {
			return true, false, err
		}
		typeName := "i64"
		if word {
			typeName = "i32"
		}
		changed := c.newTmp()
		switch {
		case strings.HasPrefix(string(op), "CINC"):
			fmt.Fprintf(c.b, "  %%%s = add %s %s, 1\n", changed, typeName, src)
		case strings.HasPrefix(string(op), "CINV"):
			fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", changed, typeName, src)
		case strings.HasPrefix(string(op), "CNEG"):
			fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", changed, typeName, src)
		}
		cv, err := c.condValue(cond)
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %%%s, %s %s\n", out, cv, typeName, changed, typeName, src)
		return true, false, c.storeCondResult(ins.Args[2].Reg, "%"+out, word)
	}
	return false, false, nil
}

func arm64ConditionOperand(op asm.Operand) (string, bool) {
	if op.Kind == asm.OpIdent {
		return op.Ident, true
	}
	// AL is also an x86 byte-register spelling in the architecture-neutral
	// parser. Its position in an ARM64 conditional instruction is unambiguous.
	if op.Kind == asm.OpReg && strings.EqualFold(string(op.Reg), "AL") {
		return "AL", true
	}
	return "", false
}

func (c *arm64Ctx) loadCondOperand(op asm.Operand, word bool) (string, error) {
	v, err := c.eval64(op, false)
	if err != nil {
		return "", err
	}
	if !word {
		return v, nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v)
	return "%" + t, nil
}

func (c *arm64Ctx) storeCondResult(dst asm.Reg, value string, word bool) error {
	if word {
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, value)
		value = "%" + z
	}
	return c.storeReg(dst, value)
}
