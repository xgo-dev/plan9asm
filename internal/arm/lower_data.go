package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *armCtx) lowerData(op, cond string, postInc bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	return c.lowerDataWithFlags(op, cond, postInc, false, ins)
}

func (c *armCtx) lowerDataWithFlags(op, cond string, postInc, setFlags bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "MOVD", "MOVF":
		return true, false, c.lowerARMMOVFOrD(op, cond, postInc, ins)
	case "MOVW":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm MOVW expects 2 operands: %q", ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		if cond != "" && (dst.Kind == asm.OpMem || dst.Kind == asm.OpFP || dst.Kind == asm.OpSym || dst.Kind == asm.OpIdent) {
			err := c.emitConditionalEffect(cond, func() error {
				_, _, err := c.lowerDataWithFlags(op, "", postInc, setFlags, ins)
				return err
			})
			return true, false, err
		}
		v := ""
		shiftCarry := ""
		carryDef := false
		if src.Kind == asm.OpMem {
			v, err = c.loadMem(src.Mem, 32, postInc, false)
		} else if src.Kind == asm.OpReg && strings.HasPrefix(string(src.Reg), "F") {
			raw, ferr := c.loadFReg(src.Reg)
			if ferr != nil {
				return true, false, ferr
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, raw)
			v = "%" + tr
		} else if setFlags && src.Kind == asm.OpRegShift {
			v, shiftCarry, err = c.evalShiftWithCarry(src, true)
			carryDef = armRegShiftDefinesCarry(src)
		} else {
			v, err = c.eval32(src, false)
		}
		if err != nil {
			return true, false, err
		}
		if dst.Kind == asm.OpReg && strings.HasPrefix(string(dst.Reg), "F") {
			ext := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", ext, v)
			v64 := "%" + ext
			if cond == "" || strings.EqualFold(cond, "AL") {
				return true, false, c.storeFReg(dst.Reg, v64)
			}
			cv, cerr := c.condValue(cond)
			if cerr != nil {
				return true, false, cerr
			}
			oldV, ferr := c.loadFReg(dst.Reg)
			if ferr != nil {
				return true, false, ferr
			}
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %s, i64 %s\n", sel, cv, v64, oldV)
			return true, false, c.storeFReg(dst.Reg, "%"+sel)
		}
		if err := c.storeARMValue(dst, v, 32, cond, postInc, ins.Raw); err != nil {
			return true, false, err
		}
		if setFlags && dst.Kind == asm.OpReg {
			return true, false, c.setFlagsLogicCarry(cond, v, shiftCarry, carryDef)
		}
		return true, false, nil
	case "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm %s expects 2 operands: %q", op, ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		if cond != "" && (dst.Kind == asm.OpMem || dst.Kind == asm.OpFP || dst.Kind == asm.OpSym) {
			err := c.emitConditionalEffect(cond, func() error {
				_, _, err := c.lowerData(op, "", postInc, ins)
				return err
			})
			return true, false, err
		}
		v := ""
		bits := 8
		if op == "MOVH" || op == "MOVHS" || op == "MOVHU" {
			bits = 16
		}
		signed := op == "MOVB" || op == "MOVBS" || op == "MOVH" || op == "MOVHS"
		switch src.Kind {
		case asm.OpMem:
			v, err = c.loadMem(src.Mem, bits, postInc, signed)
		case asm.OpSym:
			if strings.HasPrefix(strings.TrimSpace(src.Sym), "$") {
				v, err = c.eval32(src, false)
			} else {
				p, perr := c.ptrFromSB(src.Sym)
				if perr != nil {
					return true, false, perr
				}
				ld, ext := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s\n", ld, bits, p)
				if signed {
					fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", ext, bits, ld)
				} else {
					fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i32\n", ext, bits, ld)
				}
				v = "%" + ext
			}
		default:
			v, err = c.eval32(src, false)
			if err == nil && dst.Kind == asm.OpReg {
				tr, ext := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i%d\n", tr, v, bits)
				if signed {
					fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", ext, bits, tr)
				} else {
					fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i32\n", ext, bits, tr)
				}
				v = "%" + ext
			}
		}
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeARMValue(dst, v, bits, cond, postInc, ins.Raw)
	}
	return false, false, nil
}

func (c *armCtx) emitConditionalEffect(cond string, emit func() error) error {
	if cond == "" || strings.EqualFold(cond, "AL") {
		return emit()
	}
	cv, err := c.condValue(cond)
	if err != nil {
		return err
	}
	id := c.newTmp()
	taken := armLLVMBlockName("cond_effect_taken_" + id)
	done := armLLVMBlockName("cond_effect_done_" + id)
	fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", cv, taken, done)
	fmt.Fprintf(c.b, "\n%s:\n", taken)
	savedFlagsDef := c.flagsDef
	if err := emit(); err != nil {
		return err
	}
	// Meet the skip edge (savedFlagsDef) and taken edge (c.flagsDef):
	// conditional writes cannot newly define flags, while conditional calls
	// still invalidate flags after the merge.
	c.flagsDef = savedFlagsDef & c.flagsDef
	fmt.Fprintf(c.b, "  br label %%%s\n", done)
	fmt.Fprintf(c.b, "\n%s:\n", done)
	return nil
}

func (c *armCtx) selectRegWrite(dst asm.Reg, cond string, newV string) error {
	if cond == "" || strings.EqualFold(cond, "AL") {
		return c.storeReg(dst, newV)
	}
	cv, err := c.condValue(cond)
	if err != nil {
		return err
	}
	oldV, err := c.loadReg(dst)
	if err != nil {
		return err
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 %s, i32 %s\n", t, cv, newV, oldV)
	return c.storeReg(dst, "%"+t)
}

func (c *armCtx) storeARMValue(dst asm.Operand, v string, bits int, cond string, postInc bool, raw string) error {
	switch dst.Kind {
	case asm.OpReg:
		// ARM register file holds full words; loads already extended to i32.
		return c.selectRegWrite(dst.Reg, cond, v)
	case asm.OpMem:
		if cond != "" {
			return fmt.Errorf("arm conditional store to memory unsupported: %q", raw)
		}
		return c.storeMem(dst.Mem, bits, postInc, v)
	case asm.OpFP:
		if cond != "" {
			return fmt.Errorf("arm conditional store to FP slot unsupported: %q", raw)
		}
		return c.storeFP32(dst.FPOffset, v)
	case asm.OpSym:
		if cond != "" {
			return fmt.Errorf("arm conditional store to symbol unsupported: %q", raw)
		}
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		switch bits {
		case 32:
			fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n", v, p)
		case 16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", t, v)
			fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", t, p)
		case 8:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i8\n", t, v)
			fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s\n", t, p)
		default:
			return fmt.Errorf("arm: unsupported symbol store bits %d", bits)
		}
		return nil
	case asm.OpIdent:
		switch strings.ToUpper(dst.Ident) {
		case "CPSR":
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "msr cpsr_fsxc, $0", "r,~{cc},~{memory}", v)
			c.storeFlagsFromStatus(v)
			return nil
		case "FPCR", "FPSR":
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "vmsr fpscr, $0", "r,~{memory}", v)
			return nil
		default:
			return fmt.Errorf("arm unsupported system register %q: %q", dst.Ident, raw)
		}
	default:
		return fmt.Errorf("arm unsupported dst operand: %q", raw)
	}
}
