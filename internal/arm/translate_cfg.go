package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func TranslateFunc(b *strings.Builder, fn asm.Func, sig asm.FuncSig, resolve func(string) string, sigs map[string]asm.FuncSig, annotateSource bool) error {
	fmt.Fprintf(b, "define %s %s(", sig.Ret, asm.LLVMGlobal(sig.Name))
	for i, t := range sig.Args {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s %%arg%d", t, i)
	}
	b.WriteString(")")
	if sig.Attrs != "" {
		b.WriteString(" " + sig.Attrs)
	}
	b.WriteString(" {\n")

	c := newARMCtx(b, fn, sig, resolve, sigs, annotateSource)
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		return err
	}
	if err := c.lowerBlocks(); err != nil {
		return err
	}

	b.WriteString("}\n")
	return nil
}

func (c *armCtx) lowerBlocks() error {
	emitBr := func(target string) {
		fmt.Fprintf(c.b, "  br label %%%s\n", armLLVMBlockName(target))
	}
	emitCondBr := func(cond string, target string, fall string) error {
		cv, err := c.condValue(cond)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", cv, armLLVMBlockName(target), armLLVMBlockName(fall))
		return nil
	}

	for bi := 0; bi < len(c.blocks); bi++ {
		blk := c.blocks[bi]
		if bi != 0 {
			fmt.Fprintf(c.b, "\n%s:\n", armLLVMBlockName(blk.name))
		}
		terminated := false
		for _, ins := range blk.instrs {
			c.emitSourceComment(ins)
			term, err := c.lowerInstr(bi, ins, emitBr, emitCondBr)
			if err != nil {
				return err
			}
			if term {
				terminated = true
				break
			}
		}
		if terminated {
			continue
		}
		if bi+1 < len(c.blocks) {
			emitBr(c.blocks[bi+1].name)
			continue
		}
		c.lowerRetZero()
	}
	return nil
}

func (c *armCtx) lowerInstr(bi int, ins asm.Instr, emitBr armEmitBr, emitCondBr armEmitCondBr) (bool, error) {
	rawOp := strings.ToUpper(string(ins.Op))
	baseOp, cond, postInc, setFlags := armDecodeOp(rawOp)
	preInc, subOff := armDecodeAddrModes(rawOp)
	c.curPreInc = preInc
	c.curSubOff = subOff
	defer func() {
		c.curPreInc = false
		c.curSubOff = false
	}()
	switch baseOp {
	case string(asm.OpTEXT), string(asm.OpBYTE):
		return false, nil
	case string(asm.OpRET):
		if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, c.tailCallAndRet(ins.Args[0])
		}
		if len(ins.Args) > 1 {
			return true, fmt.Errorf("arm RET expects at most 1 operand: %q", ins.Raw)
		}
		return true, c.lowerRET()
	case "UNDEF":
		c.b.WriteString("  call void asm sideeffect \"udf #0\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, nil
	case "MOVM":
		if ok, term, err := c.lowerMOVM(rawOp, ins); ok {
			return term, err
		}
		return false, fmt.Errorf("arm: unsupported instruction %s", ins.Op)
	case "PCDATA", "FUNCDATA", "NO_LOCAL_POINTERS", string(asm.OpWORD), "DWORD", "NOP", "DMB", "#IFDEF", "#ELSE", "#ENDIF":
		return false, nil
	}
	if ok, term, err := c.lowerData(baseOp, cond, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerDeclarative(baseOp, cond, postInc, setFlags, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(baseOp, cond, setFlags, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomic(baseOp, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSyscall(baseOp, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerBranch(bi, baseOp, cond, ins, emitBr, emitCondBr); ok {
		return term, err
	}
	return false, fmt.Errorf("arm: unsupported instruction %s", ins.Op)
}

func (c *armCtx) lowerRET() error {
	if len(c.fpResults) == 0 {
		r0, err := c.loadReg(asm.Reg("R0"))
		if err != nil {
			return err
		}
		switch c.sig.Ret {
		case asm.Void:
			c.b.WriteString("  ret void\n")
		case asm.I1, asm.I8, asm.I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", t, r0, c.sig.Ret)
			fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, t)
		case asm.I32:
			fmt.Fprintf(c.b, "  ret i32 %s\n", r0)
		case asm.Ptr:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", t, r0)
			fmt.Fprintf(c.b, "  ret ptr %%%s\n", t)
		default:
			return fmt.Errorf("arm: unsupported return type %s", c.sig.Ret)
		}
		return nil
	}
	if len(c.fpResults) == 1 {
		slot := c.fpResults[0]
		var v string
		var err error
		if c.fpResWritten[slot.Index] || c.fpResAddrTaken[slot.Index] {
			v, err = c.loadFPResult(slot)
		} else {
			v, err = c.loadRetSlotFallback(slot)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, v)
		return nil
	}
	if c.sig.Ret == asm.I64 && len(c.fpResults) == 2 && c.fpResults[0].Type == asm.I32 && c.fpResults[1].Type == asm.I32 {
		parts := make([]string, 2)
		for i, slot := range c.fpResults {
			var err error
			if c.fpResWritten[slot.Index] || c.fpResAddrTaken[slot.Index] {
				parts[i], err = c.loadFPResult(slot)
			} else {
				parts[i], err = c.loadRetSlotFallback(slot)
			}
			if err != nil {
				return err
			}
		}
		lo := c.newTmp()
		hi := c.newTmp()
		shifted := c.newTmp()
		joined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", lo, parts[0])
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", hi, parts[1])
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", shifted, hi)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", joined, lo, shifted)
		fmt.Fprintf(c.b, "  ret i64 %%%s\n", joined)
		return nil
	}
	cur := "undef"
	last := ""
	for _, slot := range c.fpResults {
		var v string
		var err error
		if c.fpResWritten[slot.Index] || c.fpResAddrTaken[slot.Index] {
			v, err = c.loadFPResult(slot)
		} else {
			v, err = c.loadRetSlotFallback(slot)
		}
		if err != nil {
			return err
		}
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", name, c.sig.Ret, cur, slot.Type, v, slot.Index)
		cur = "%" + name
		last = cur
	}
	fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, last)
	return nil
}

func (c *armCtx) lowerRetZero() {
	switch c.sig.Ret {
	case asm.Void:
		c.b.WriteString("  ret void\n")
	case asm.I1:
		c.b.WriteString("  ret i1 false\n")
	case asm.Ptr:
		c.b.WriteString("  ret ptr null\n")
	default:
		fmt.Fprintf(c.b, "  ret %s 0\n", c.sig.Ret)
	}
}
