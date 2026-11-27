package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *armCtx) lowerArith(op, cond string, setFlags bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "ADD", "SUB", "AND", "ORR", "EOR", "RSB", "BIC":
		return true, false, c.lowerARMALU(op, cond, setFlags, ins)
	case "MVN":
		return true, false, c.lowerARMMVN(cond, setFlags, ins)
	case "ADC", "SBC":
		return true, false, c.lowerARMADCSBC(op, cond, setFlags, ins)
	case "MUL", "MULU":
		return true, false, c.lowerARMMUL(cond, ins)
	case "MULLU":
		return true, false, c.lowerARMMULLU(cond, ins)
	case "MULA":
		return true, false, c.lowerARMMULA(cond, ins)
	case "MULAL", "MULALU":
		return true, false, c.lowerARMMULAL(cond, ins)
	case "MULAWT":
		return true, false, c.lowerARMMULAWT(cond, ins)
	case "DIVUHW":
		return true, false, c.lowerARMDIVUHW(cond, ins)
	case "CLZ":
		return true, false, c.lowerARMCLZ(cond, ins)
	case "MRC":
		return true, false, c.lowerARMMRC(ins)
	case "CMP", "CMN", "TST", "TEQ":
		return true, false, c.lowerARMCompare(op, ins)
	}
	return false, false, nil
}

func (c *armCtx) lowerARMALU(op, cond string, setFlags bool, ins asm.Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	var src, lhs, shiftCarry string
	dst := asm.Operand{}
	var err error
	isLogicOp := op == "AND" || op == "ORR" || op == "EOR" || op == "BIC"
	evalSrc := func(arg asm.Operand) (string, error) {
		if setFlags && isLogicOp && arg.Kind == asm.OpRegShift {
			v, cf, serr := c.evalShiftWithCarry(arg, true)
			shiftCarry = cf
			return v, serr
		}
		return c.eval32(arg, false)
	}
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = evalSrc(ins.Args[0])
		if err != nil {
			return err
		}
		lhs, err = c.loadReg(dst.Reg)
		if err != nil {
			return err
		}
	} else {
		dst = ins.Args[2]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = evalSrc(ins.Args[0])
		if err != nil {
			return err
		}
		lhs, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
	}
	t := c.newTmp()
	switch op {
	case "ADD":
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", t, lhs, src)
	case "SUB":
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t, lhs, src)
	case "AND":
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %s\n", t, lhs, src)
	case "ORR":
		fmt.Fprintf(c.b, "  %%%s = or i32 %s, %s\n", t, lhs, src)
	case "EOR":
		fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", t, lhs, src)
	case "RSB":
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t, src, lhs)
	case "BIC":
		n := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i32 %s, -1\n", n, src)
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %%%s\n", t, lhs, n)
	}
	if err := c.selectRegWrite(dst.Reg, cond, "%"+t); err != nil {
		return err
	}
	if !setFlags {
		return nil
	}
	switch op {
	case "ADD":
		return c.setFlagsAdd(cond, lhs, src, "%"+t)
	case "SUB":
		return c.setFlagsSub(cond, lhs, src, "%"+t)
	case "RSB":
		return c.setFlagsSub(cond, src, lhs, "%"+t)
	case "AND", "ORR", "EOR", "BIC":
		return c.setFlagsLogicCarry(cond, "%"+t, shiftCarry)
	default:
		return nil
	}
}

func (c *armCtx) lowerARMCompare(op string, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("arm %s expects 2 operands: %q", op, ins.Raw)
	}
	var src, shiftCarry string
	var err error
	if (op == "TST" || op == "TEQ") && ins.Args[0].Kind == asm.OpRegShift {
		src, shiftCarry, err = c.evalShiftWithCarry(ins.Args[0], true)
	} else {
		src, err = c.eval32(ins.Args[0], false)
	}
	if err != nil {
		return err
	}
	lhs, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	res := c.newTmp()
	switch op {
	case "CMP":
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsSub("", lhs, src, "%"+res); err != nil {
			return err
		}
	case "CMN":
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsAdd("", lhs, src, "%"+res); err != nil {
			return err
		}
	case "TST":
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsLogicCarry("", "%"+res, shiftCarry); err != nil {
			return err
		}
	case "TEQ":
		fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", res, lhs, src)
		if err := c.setFlagsLogicCarry("", "%"+res, shiftCarry); err != nil {
			return err
		}
	}
	return nil
}

func (c *armCtx) lowerARMMVN(cond string, setFlags bool, ins asm.Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm MVN expects 2 or 3 operands: %q", ins.Raw)
	}
	var src, shiftCarry string
	var dst asm.Operand
	var err error
	srcArg := ins.Args[0]
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
	} else {
		srcArg = ins.Args[1]
		dst = ins.Args[2]
	}
	if setFlags && srcArg.Kind == asm.OpRegShift {
		src, shiftCarry, err = c.evalShiftWithCarry(srcArg, true)
	} else {
		src, err = c.eval32(srcArg, false)
	}
	if err != nil {
		return err
	}
	if dst.Kind != asm.OpReg {
		return fmt.Errorf("arm MVN dst must be reg: %q", ins.Raw)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i32 %s, -1\n", t, src)
	if err := c.selectRegWrite(dst.Reg, cond, "%"+t); err != nil {
		return err
	}
	if setFlags {
		return c.setFlagsLogicCarry(cond, "%"+t, shiftCarry)
	}
	return nil
}

func (c *armCtx) lowerARMADCSBC(op, cond string, setFlags bool, ins asm.Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects 2 or 3 operands: %q", op, ins.Raw)
	}
	var src, lhs string
	dst := asm.Operand{}
	var err error
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.loadReg(dst.Reg)
		if err != nil {
			return err
		}
	} else {
		dst = ins.Args[2]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm %s dst must be reg: %q", op, ins.Raw)
		}
		src, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		lhs, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
	}
	cf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", cf, c.flagsCSlot)
	cin := c.newTmp()
	if op == "SBC" {
		ncf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", ncf, cf)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", cin, ncf)
	} else {
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", cin, cf)
	}
	t0 := c.newTmp()
	if op == "SBC" {
		fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", t0, lhs, src)
	} else {
		fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", t0, lhs, src)
	}
	res := c.newTmp()
	if op == "SBC" {
		fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, %%%s\n", res, t0, cin)
	} else {
		fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", res, t0, cin)
	}
	if err := c.selectRegWrite(dst.Reg, cond, "%"+res); err != nil {
		return err
	}
	if setFlags {
		if op == "ADC" {
			l64 := c.newTmp()
			s64 := c.newTmp()
			c64 := c.newTmp()
			total1 := c.newTmp()
			total2 := c.newTmp()
			carry := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", l64, lhs)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", s64, src)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", c64, cin)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", total1, l64, s64)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", total2, total1, c64)
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i64 %%%s, 4294967295\n", carry, total2)
			if err := c.setFlagsAdd(cond, lhs, src, "%"+res); err != nil {
				return err
			}
			if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+carry); err != nil {
				return err
			}
		} else {
			l64 := c.newTmp()
			s64 := c.newTmp()
			b64 := c.newTmp()
			subtr := c.newTmp()
			borrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", l64, lhs)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", s64, src)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", b64, cin)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", subtr, s64, b64)
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %%%s\n", borrow, l64, subtr)
			if err := c.setFlagsSub(cond, lhs, src, "%"+res); err != nil {
				return err
			}
			nb := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", nb, borrow)
			if err := c.storeFlagCond(cond, c.flagsCSlot, "%"+nb); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *armCtx) selectRegPairWrite(hi, lo asm.Reg, cond, newHi, newLo string) error {
	if cond == "" {
		if err := c.storeReg(hi, newHi); err != nil {
			return err
		}
		return c.storeReg(lo, newLo)
	}
	cv, err := c.condValue(cond)
	if err != nil {
		return err
	}
	oldHi, err := c.loadReg(hi)
	if err != nil {
		return err
	}
	oldLo, err := c.loadReg(lo)
	if err != nil {
		return err
	}
	selHi := c.newTmp()
	selLo := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 %s, i32 %s\n", selHi, cv, newHi, oldHi)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 %s, i32 %s\n", selLo, cv, newLo, oldLo)
	if err := c.storeReg(hi, "%"+selHi); err != nil {
		return err
	}
	return c.storeReg(lo, "%"+selLo)
}

func (c *armCtx) lowerARMMUL(cond string, ins asm.Instr) error {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fmt.Errorf("arm MUL expects 2 or 3 operands: %q", ins.Raw)
	}
	var a, b string
	var dst asm.Operand
	var err error
	if len(ins.Args) == 2 {
		dst = ins.Args[1]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm MUL dst must be reg: %q", ins.Raw)
		}
		a, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err = c.loadReg(dst.Reg)
		if err != nil {
			return err
		}
	} else {
		dst = ins.Args[2]
		if dst.Kind != asm.OpReg {
			return fmt.Errorf("arm MUL dst must be reg: %q", ins.Raw)
		}
		a, err = c.eval32(ins.Args[0], false)
		if err != nil {
			return err
		}
		b, err = c.eval32(ins.Args[1], false)
		if err != nil {
			return err
		}
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", t, a, b)
	return c.selectRegWrite(dst.Reg, cond, "%"+t)
}

func (c *armCtx) lowerARMMULLU(cond string, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpRegList || len(ins.Args[2].RegList) != 2 {
		return fmt.Errorf("arm MULLU expects src, lhs, (hi,lo): %q", ins.Raw)
	}
	a, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	b, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	a64 := c.zextI32ToI64(a)
	b64 := c.zextI32ToI64(b)
	prod := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", prod, a64, b64)
	lo := c.newTmp()
	hiShift := c.newTmp()
	hi := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo, prod)
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiShift, prod)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiShift)
	return c.selectRegPairWrite(ins.Args[2].RegList[0], ins.Args[2].RegList[1], cond, "%"+hi, "%"+lo)
}

func (c *armCtx) lowerARMMULA(cond string, ins asm.Instr) error {
	if len(ins.Args) != 4 || ins.Args[3].Kind != asm.OpReg {
		return fmt.Errorf("arm MULA expects a, b, acc, dst: %q", ins.Raw)
	}
	a, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	b, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	acc, err := c.eval32(ins.Args[2], false)
	if err != nil {
		return err
	}
	mul := c.newTmp()
	res := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i32 %s, %s\n", mul, a, b)
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %s\n", res, mul, acc)
	return c.selectRegWrite(ins.Args[3].Reg, cond, "%"+res)
}

func (c *armCtx) lowerARMMULAL(cond string, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpRegList || len(ins.Args[2].RegList) != 2 {
		return fmt.Errorf("arm MULAL expects a, b, (hi,lo): %q", ins.Raw)
	}
	hiReg := ins.Args[2].RegList[0]
	loReg := ins.Args[2].RegList[1]
	a, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	b, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	oldHi, err := c.loadReg(hiReg)
	if err != nil {
		return err
	}
	oldLo, err := c.loadReg(loReg)
	if err != nil {
		return err
	}
	oldHi64 := c.zextI32ToI64(oldHi)
	oldLo64 := c.zextI32ToI64(oldLo)
	hiSh := c.newTmp()
	old64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i64 %s, 32\n", hiSh, oldHi64)
	fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", old64, hiSh, oldLo64)
	prod := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %s\n", prod, c.zextI32ToI64(a), c.zextI32ToI64(b))
	sum := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", sum, old64, prod)
	lo := c.newTmp()
	hiShift := c.newTmp()
	hi := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo, sum)
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiShift, sum)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiShift)
	return c.selectRegPairWrite(hiReg, loReg, cond, "%"+hi, "%"+lo)
}

func (c *armCtx) lowerARMMULAWT(cond string, ins asm.Instr) error {
	if len(ins.Args) != 4 || ins.Args[3].Kind != asm.OpReg {
		return fmt.Errorf("arm MULAWT expects a, b, acc, dst: %q", ins.Raw)
	}
	a, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	b, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	acc, err := c.eval32(ins.Args[2], false)
	if err != nil {
		return err
	}
	a64 := c.newTmp()
	b64 := c.newTmp()
	prod := c.newTmp()
	hiShift := c.newTmp()
	hi := c.newTmp()
	res := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", a64, a)
	fmt.Fprintf(c.b, "  %%%s = sext i32 %s to i64\n", b64, b)
	fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", prod, a64, b64)
	fmt.Fprintf(c.b, "  %%%s = ashr i64 %%%s, 32\n", hiShift, prod)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi, hiShift)
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %s\n", res, hi, acc)
	return c.selectRegWrite(ins.Args[3].Reg, cond, "%"+res)
}

func (c *armCtx) lowerARMDIVUHW(cond string, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm DIVUHW expects divisor, numerator, dst: %q", ins.Raw)
	}
	divisor, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	numer, err := c.eval32(ins.Args[1], false)
	if err != nil {
		return err
	}
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", zero, divisor)
	div := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = udiv i32 %s, %s\n", div, numer, divisor)
	sel := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 0, i32 %%%s\n", sel, zero, div)
	return c.selectRegWrite(ins.Args[2].Reg, cond, "%"+sel)
}

func (c *armCtx) lowerARMCLZ(cond string, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("arm CLZ expects src, dst: %q", ins.Raw)
	}
	src, err := c.eval32(ins.Args[0], false)
	if err != nil {
		return err
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctlz.i32(i32 %s, i1 false)\n", t, src)
	return c.selectRegWrite(ins.Args[1].Reg, cond, "%"+t)
}

func (c *armCtx) lowerARMMRC(ins asm.Instr) error {
	if len(ins.Args) != 6 || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm MRC expects coproc, opc1, dst, CRn, CRm, opc2: %q", ins.Raw)
	}
	part := func(op asm.Operand) string {
		s := strings.ToLower(strings.TrimSpace(op.String()))
		return strings.TrimPrefix(s, "$")
	}
	// LLVM inline asm refers to the single output register via $0.
	asm := fmt.Sprintf("mrc p%s, %s, $0, %s, %s, %s", part(ins.Args[0]), part(ins.Args[1]), part(ins.Args[3]), part(ins.Args[4]), part(ins.Args[5]))
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", t, asm, "=r,~{memory}")
	return c.storeReg(ins.Args[2].Reg, "%"+t)
}
