package plan9asm

import (
	"fmt"
	"strings"
)

func (c *armCtx) lowerData(op, cond string, postInc bool, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerIntegerMemoryMove(op, cond, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "MOVF", "MOVD":
		return c.lowerARMFloatMove(op, cond, ins)
	case "MOVW":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm MOVW expects 2 operands: %q", ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		srcF := src.Kind == OpReg && isARMFReg(src.Reg)
		dstF := dst.Kind == OpReg && isARMFReg(dst.Reg)
		if srcF || dstF {
			if err := armRequireConditionOnlySuffix(ins); err != nil {
				return true, false, err
			}
			srcR := src.Kind == OpReg && isARMGeneralReg(src.Reg) && !srcF
			dstR := dst.Kind == OpReg && isARMGeneralReg(dst.Reg) && !dstF
			if (!srcR || !dstF) && (!srcF || !dstR) {
				return true, false, fmt.Errorf("arm MOVW R/F bit transfer expects Rsrc,Fdst or Fsrc,Rdst: %q", ins.Raw)
			}
			if cond != "" && !strings.EqualFold(cond, "AL") {
				err := c.emitConditionalEffect(cond, func() error {
					_, _, innerErr := c.lowerData(op, "", postInc, ins)
					return innerErr
				})
				return true, false, err
			}
			if srcR {
				value, loadErr := c.loadReg(src.Reg)
				if loadErr != nil {
					return true, false, loadErr
				}
				return true, false, c.selectFRegWrite(dst.Reg, "", c.normalizeARMFloatBits(value, 32))
			}
			value, loadErr := c.loadFReg(src.Reg)
			if loadErr != nil {
				return true, false, loadErr
			}
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, value)
			return true, false, c.storeReg(dst.Reg, "%"+narrow)
		}
		if cond != "" && (dst.Kind == OpMem || dst.Kind == OpFP || dst.Kind == OpSym || dst.Kind == OpIdent) {
			err := c.emitConditionalEffect(cond, func() error {
				_, _, err := c.lowerData(op, "", postInc, ins)
				return err
			})
			return true, false, err
		}
		v := ""
		if src.Kind == OpMem {
			v, err = c.loadMem(src.Mem, 32, postInc, false)
		} else {
			v, err = c.eval32(src, false)
		}
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeARMValue(dst, v, 32, cond, postInc, ins.Raw)
	case "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm %s expects 2 operands: %q", op, ins.Raw)
		}
		src, dst := ins.Args[0], ins.Args[1]
		if cond != "" && (dst.Kind == OpMem || dst.Kind == OpFP || dst.Kind == OpSym) {
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
		if src.Kind == OpMem {
			v, err = c.loadMem(src.Mem, bits, postInc, op == "MOVB" || op == "MOVBS" || op == "MOVH" || op == "MOVHS")
		} else {
			v, err = c.eval32(src, false)
			if err == nil && (op == "MOVBS" || op == "MOVHS") {
				narrow := c.newTmp()
				extended := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i%d\n", narrow, v, bits)
				fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", extended, bits, narrow)
				v = "%" + extended
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
	if err := emit(); err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  br label %%%s\n", done)
	fmt.Fprintf(c.b, "\n%s:\n", done)
	return nil
}

func (c *armCtx) selectRegWrite(dst Reg, cond string, newV string) error {
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

func (c *armCtx) storeARMValue(dst Operand, v string, bits int, cond string, postInc bool, raw string) error {
	switch dst.Kind {
	case OpReg:
		// ARM register file holds full words; loads already extended to i32.
		return c.selectRegWrite(dst.Reg, cond, v)
	case OpMem:
		if cond != "" {
			return fmt.Errorf("arm conditional store to memory unsupported: %q", raw)
		}
		return c.storeMem(dst.Mem, bits, postInc, v)
	case OpFP:
		if cond != "" {
			return fmt.Errorf("arm conditional store to FP slot unsupported: %q", raw)
		}
		return c.storeFP32(dst.FPOffset, v)
	case OpSym:
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
	case OpIdent:
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
