package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/exclusive"
	"strings"
)

// CollectKuserCASFuncs identifies local Linux/ARM __kuser_cmpxchg trampolines
// (functions whose sole executable instruction is `MOVW $0xffff0fc0, R15`).
func CollectKuserCASFuncs(funcs []asm.Func, resolve func(string) string) map[string]bool {
	var out map[string]bool
	for _, fn := range funcs {
		if !isARMKuserCASFunc(fn) {
			continue
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[resolve(fn.Sym)] = true
	}
	return out
}

func isARMKuserCASFunc(fn asm.Func) bool {
	var ins *asm.Instr
	for i := range fn.Instrs {
		candidate := &fn.Instrs[i]
		switch strings.ToUpper(string(candidate.Op)) {
		case string(asm.OpTEXT), "PCDATA", "FUNCDATA", "NO_LOCAL_POINTERS", "NOP", "#IFDEF", "#ELSE", "#ENDIF":
			continue
		default:
			if ins != nil {
				return false
			}
			ins = candidate
		}
	}
	if ins == nil {
		return false
	}
	if strings.ToUpper(string(ins.Op)) != "MOVW" || len(ins.Args) != 2 {
		return false
	}
	if ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" || uint32(ins.Args[0].Imm) != 0xffff0fc0 {
		return false
	}
	if ins.Args[1].Kind != asm.OpReg {
		return false
	}
	r := strings.ToUpper(string(ins.Args[1].Reg))
	return r == "R15" || r == "PC"
}

func TranslateFunc(b *strings.Builder, fn asm.Func, sig asm.FuncSig, resolve func(string) string, sigs map[string]asm.FuncSig, annotateSource bool) error {
	return TranslateFuncWithKuserCAS(b, fn, sig, resolve, sigs, nil, "", annotateSource)
}

func TranslateFuncWithKuserCAS(b *strings.Builder, fn asm.Func, sig asm.FuncSig, resolve func(string) string, sigs map[string]asm.FuncSig, kuserCAS map[string]bool, targetTriple string, annotateSource bool) error {
	c := newARMCtx(b, fn, sig, resolve, sigs, annotateSource)
	targetTriple = strings.ToLower(targetTriple)
	apple := strings.Contains(targetTriple, "-apple-") || strings.Contains(targetTriple, "-darwin") || strings.Contains(targetTriple, "-ios")
	lowered, groups, err := exclusive.Rewrite(fn, false, apple)
	if err != nil {
		return err
	}
	if len(groups) > 0 {
		c.exclusive = groups
		c.blocks = armSplitBlocks(lowered)
	}

	c.kuserCAS = kuserCAS
	c.nativeA32 = supportsA32(targetTriple)
	c.linuxA32 = c.nativeA32 && strings.Contains("-"+targetTriple+"-", "-linux-")
	blockDef, blockTouched, reachable := c.computeBlockFlagsDefIn()
	header := func(name string) string {
		params := make([]string, len(sig.Args))
		for i, typ := range sig.Args {
			params[i] = fmt.Sprintf("%s %%arg%d", typ, i)
		}
		return fmt.Sprintf("%s %s(%s)", sig.Ret, asm.LLVMGlobal(name), strings.Join(params, ", "))
	}
	if kuserCAS[sig.Name] {
		if !c.linuxA32 {
			return fmt.Errorf("%w: Linux kuser trampoline requires a Linux A32 target", asm.ErrProbeNeedsContext)
		}
		// The address of the trampoline can escape or be linked from another
		// object. Preserve its register ABI for calls we could not inline.
		c.emitNakedTransfer(header(sig.Name), "ldr pc, [pc, #-4]\\0A\\09.word 0xffff0fc0", "")
		return nil
	}
	if c.needsEntryCPSR {
		if err := c.emitEntryCPSRWrapper(header(sig.Name)); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(b, "define %s %s {\n", header(sig.Name), sig.Attrs)
	}
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		return err
	}
	if err := c.lowerBlocks(blockDef, blockTouched, reachable); err != nil {
		return err
	}

	b.WriteString("}\n")
	return nil
}

func (c *armCtx) lowerBlocks(blockFlagsDefIn, blockFlagsTouchedIn []armFlagMask, blockReachable []bool) error {
	emitBr := func(target string) {
		fmt.Fprintf(c.b, "  br label %%%s\n", armLLVMBlockName(target))
	}
	emitCondBr := func(cond string, target string, fall string) error {
		if c.exclusiveExit != "" {
			fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", c.exclusiveExit, armLLVMBlockName(target), armLLVMBlockName(fall))
			c.exclusiveExit = ""
			return nil
		}
		cv, err := c.condValue(cond)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", cv, armLLVMBlockName(target), armLLVMBlockName(fall))
		return nil
	}

	for bi := 0; bi < len(c.blocks); bi++ {
		blk := c.blocks[bi]
		if !blockReachable[bi] {
			if bi != 0 {
				fmt.Fprintf(c.b, "\n%s:\n", armLLVMBlockName(blk.name))
				c.b.WriteString("  unreachable\n")
			}
			continue
		}
		c.flagsDef = blockFlagsDefIn[bi]
		c.flagsTouched = blockFlagsTouchedIn[bi]
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
	if (baseOp == "WORD" || baseOp == "DMB" || strings.HasPrefix(baseOp, "LDREX") || strings.HasPrefix(baseOp, "STREX")) && (setFlags || preInc || postInc || subOff) {
		return false, fmt.Errorf("arm: unsupported suffix on %s", rawOp)
	}
	if ins.Op == exclusive.Opcode {
		if !c.nativeA32 {
			return false, fmt.Errorf("%w: exclusive region requires a native target", asm.ErrProbeNeedsContext)
		}
		id := ins.Args[0].Imm
		return false, c.exclusive[id].Emit(c.b, c.newTmp, c.loadReg, c.storeReg, c.storeFlagsFromStatus, "", &c.exclusiveExit, c.ptrFromSB)
	}
	switch baseOp {
	case string(asm.OpTEXT):
		return false, nil
	case string(asm.OpRET):
		if cond != "" && cond != "AL" {
			pred, err := c.condValue(cond)
			if err != nil {
				return false, err
			}
			id := c.newTmp()
			fmt.Fprintf(c.b, "  br i1 %s, label %%ret_%s, label %%continue_%s\nret_%s:\n", pred, id, id, id)
			def, touched := c.flagsDef, c.flagsTouched
			if err := c.returnToCaller(ins); err != nil {
				return false, err
			}
			c.flagsDef, c.flagsTouched = def, touched
			fmt.Fprintf(c.b, "continue_%s:\n", id)
			return false, nil
		}
		return true, c.returnToCaller(ins)
	case "UNDEF":
		c.b.WriteString("  call void asm sideeffect \"udf #0\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, nil
	case string(asm.OpWORD):
		return false, c.emitConditionalEffect(cond, func() error { _, err := c.lowerRawWord(ins); return err })
	case "SWI":
		return false, c.lowerSyscall(cond, ins)
	case "DMB":
		return false, c.emitConditionalEffect(cond, func() error { return c.emitDMB(ins) })
	case "MOVM":
		if ok, term, err := c.lowerMOVM(rawOp, ins); ok {
			return term, err
		}
		return false, fmt.Errorf("arm: unsupported instruction %s", ins.Op)
	case "PCDATA", "FUNCDATA", "NO_LOCAL_POINTERS", "NOP", "#IFDEF", "#ELSE", "#ENDIF":
		return false, nil
	}
	if ok, term, err := c.lowerDataWithFlags(baseOp, cond, postInc, setFlags, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerDeclarative(baseOp, cond, postInc, setFlags, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(baseOp, cond, setFlags, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomic(baseOp, cond, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerBranch(bi, baseOp, cond, ins, emitBr, emitCondBr); ok {
		return term, err
	}
	return false, fmt.Errorf("arm: unsupported instruction %s", ins.Op)
}

func (c *armCtx) returnToCaller(ins asm.Instr) error {
	if len(ins.Args) > 1 {
		return fmt.Errorf("arm RET expects at most 1 operand: %q", ins.Raw)
	}
	if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpSym {
		return c.tailCallAndRet(ins.Args[0])
	}
	return c.lowerRET()
}

func (c *armCtx) lowerRET() error {
	if len(c.fpResults) == 0 {
		return c.returnRegisters()

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

// returnRegisters reads the direct AAPCS result after a tail transfer.
func (c *armCtx) returnRegisters() error {
	if c.sig.Ret == asm.Void {
		c.b.WriteString("  ret void\n")
		return nil
	}
	result, err := c.loadRetSlotFallback(asm.FrameSlot{Type: c.sig.Ret})
	if err == nil {
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, result)
	}
	return err
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

func supportsA32(triple string) bool {
	fields := strings.Split(strings.ToLower(triple), "-")
	arch := fields[0]
	if arch != "arm" && (!strings.HasPrefix(arch, "armv") || strings.Contains(arch[4:], "m") || strings.HasSuffix(arch, "eb")) {
		return false
	}
	for _, field := range fields[1:] {
		for _, prefix := range []string{"windows", "win32", "mingw", "cygwin"} {
			if strings.HasPrefix(field, prefix) {
				return false
			}
		}
	}
	return true
}
