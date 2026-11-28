package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/exclusive"
	"strings"
)

type arm64EmitBr func(target string)
type arm64EmitCondBr func(cond string, target string, fall string) error

func EmitPrelude(b *strings.Builder) {
	b.WriteString("declare i64 @syscall(i64, i64, i64, i64, i64, i64, i64)\n")
	b.WriteString("declare i32 @cliteErrno()\n")
	b.WriteString("declare i64 @llvm.bitreverse.i64(i64)\n")
	b.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\n")
	b.WriteString("declare i64 @llvm.bswap.i64(i64)\n")
	b.WriteString("declare i32 @llvm.bswap.i32(i32)\n")
	// AArch64 CRC32 and CRC32C intrinsics.
	// Note: B/H forms take the data operand as i32 (low bits used).
	b.WriteString("declare i32 @llvm.aarch64.crc32b(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32h(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32w(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32x(i32, i64)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32cb(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32ch(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32cw(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32cx(i32, i64)\n")
	b.WriteString("\n")
	// Attribute group used by some functions to enable optional ISA features.
	// (Example: "+crc" for hash/crc32 arm64 fast paths.)
	b.WriteString("\n")
}

func TranslateFunc(b *strings.Builder, fn asm.Func, sig asm.FuncSig, resolve func(string) string, sigs map[string]asm.FuncSig, annotateSource bool, targetTriple string) error {
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

	c := newARM64Ctx(b, fn, sig, resolve, sigs, annotateSource)
	lowered, groups, err := exclusive.Rewrite(fn, true, false)
	if err != nil {
		return err
	}
	if len(groups) > 0 {
		c.exclusive = groups
		c.blocks = arm64SplitBlocks(lowered)
	}

	c.nativeAArch64 = IsTarget(targetTriple)
	c.targetTriple = strings.ToLower(targetTriple)
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		return err
	}
	if err := c.lowerBlocks(); err != nil {
		return err
	}

	b.WriteString("}\n")
	return nil
}

func (c *arm64Ctx) lowerBlocks() error {
	flows := make([]flagBlock, len(c.blocks))
	emitBr := func(target string) {
		c.flagFlow.successors[0] = target
		fmt.Fprintf(c.b, "  br label %%%s\n", asm.LLVMBlockName(target))
	}
	emitCondBr := func(cond string, target string, fall string) error {
		cv, err := c.condValue(cond)
		if err != nil {
			return err
		}
		c.branchIf(cv, target, fall)
		return nil
	}

	for bi := 0; bi < len(c.blocks); bi++ {
		blk := c.blocks[bi]
		c.flagFlow, c.flagsDefined = &flows[bi], 0
		if bi != 0 {
			fmt.Fprintf(c.b, "\n%s:\n", asm.LLVMBlockName(blk.name))
		}

		terminated := false
		for i, ins := range blk.instrs {
			c.pc = blk.startPC + int64(i)
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

		c.flagFlow.defines = c.flagsDefined
		if terminated {
			continue
		}
		// Fallthrough to next block.
		if bi+1 < len(c.blocks) {
			emitBr(c.blocks[bi+1].name)
			continue
		}
		// Last block: implicit return zero.
		c.lowerRetZero()
	}
	return c.validateFlagInputs(flows)
}

func (c *arm64Ctx) lowerInstr(bi int, ins asm.Instr, emitBr arm64EmitBr, emitCondBr arm64EmitCondBr) (terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	postInc := strings.Contains(rawOp, ".P")
	c.curPreInc = strings.Contains(rawOp, ".W")
	defer func() { c.curPreInc = false }()
	baseOp := rawOp
	if strings.HasPrefix(baseOp, "B.") {
		baseOp = "B" + baseOp[2:]
		if baseOp == "BAL" {
			baseOp = "B"
		}
	} else if dot := strings.IndexByte(baseOp, '.'); dot >= 0 {
		baseOp = baseOp[:dot]
	}
	op := asm.Op(baseOp)
	if strings.HasPrefix(rawOp, "SAVE_R19_TO_R28(") ||
		strings.HasPrefix(rawOp, "RESTORE_R19_TO_R28(") ||
		strings.HasPrefix(rawOp, "SAVE_F8_TO_F15(") ||
		strings.HasPrefix(rawOp, "RESTORE_F8_TO_F15(") {
		return false, nil
	}

	if ins.Op == exclusive.ExitOpcode {
		if bi+1 >= len(c.blocks) || c.exclusiveExit == "" {
			return false, fmt.Errorf("invalid exclusive exit: missing predicate or fallthrough")
		}
		target, ok := c.resolveBranchTarget(bi, ins.Args[0])
		if !ok {
			return false, fmt.Errorf("invalid exclusive exit target")
		}
		c.branchIf(c.exclusiveExit, target, c.blocks[bi+1].name)
		c.exclusiveExit = ""
		return true, nil
	}
	if ins.Op == exclusive.Opcode {
		if !c.nativeAArch64 {
			return false, fmt.Errorf("%w: exclusive region requires a native target", asm.ErrProbeNeedsContext)
		}
		id := ins.Args[0].Imm
		region := c.exclusive[id]
		entryNZCV := ""
		writeFlags := c.unpackNZCV
		if region.ExitPreservesFlags && region.Flags {
			// The early exit precedes CMP. Preserve the incoming NZCV on that
			// edge and only add definitions on the path that actually ran CMP.
			entryNZCV = c.packNZCV()
			writeFlags = func(computed string) {
				defined := c.flagsDefined
				c.unpackNZCV(computed)
				c.flagsDefined = defined
				c.flagFlow.fallDefines = flagAll
			}
		}
		return false, region.Emit(c.b, c.newTmp, c.loadReg, c.storeReg, writeFlags, entryNZCV, &c.exclusiveExit, nil)
	}
	switch op {
	case asm.OpTEXT:
		return false, nil
	case asm.OpRET:
		if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, c.tailCallAndRet(ins.Args[0])
		}
		if len(ins.Args) > 1 {
			return true, fmt.Errorf("arm64 RET expects at most 1 operand: %q", ins.Raw)
		}
		return true, c.lowerRET()
	case asm.OpBYTE, "DWORD", asm.OpWORD:
		var err error
		if op == asm.OpWORD {
			err = c.lowerRawWord(ins)
		} else {
			err = fmt.Errorf("arm64: unsupported executable directive %s", ins.Raw)
		}
		if err != nil && c.flagFlow != nil {
			// A literal pool after an unconditional branch is valid data.
			// Only reachable execution of an unmodeled word fails translation.
			c.flagFlow.rawErr = err
			return false, nil
		}
		return false, err
	case "BREAK", "BRK", "UNDEF", "SB", "ISB", "DMB", "DSB", "DC":
		return c.lowerSystemEffect(op, ins)
	case "PCALIGN", "NO_LOCAL_POINTERS", "PCDATA", "FUNCDATA", "PRFM", "#UNDEF", "YIELD", "NOP",
		"STY",
		"P256ADDINLINE", "P256MULBY2INLINE", "MOV",
		"#IFDEF", "#ELSE", "#ENDIF":
		return false, nil
	}

	if ok, term, err := c.lowerData(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomic(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomicDeclarative(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVec(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVecDeclarative(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerScalarDeclarative(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFP(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFPDeclarative(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSyscall(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerCond(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerBranch(bi, op, ins, emitBr, emitCondBr); ok {
		return term, err
	}
	if ok, term, err := c.lowerSVEOrSys(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerM5Ext(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerM6XArch(op, postInc, ins); ok {
		return term, err
	}
	return false, fmt.Errorf("arm64: unsupported instruction %s", ins.Op)
}

func (c *arm64Ctx) lowerRET() error {
	// Prefer classic Go asm return slots if present; many stdlib asm functions
	// never materialize the return value in R0 and only store to ret+off(FP).
	if len(c.fpResults) == 0 {
		r0, err := c.loadReg(asm.Reg("R0"))
		if err != nil {
			return err
		}
		switch c.sig.Ret {
		case asm.Void:
			c.b.WriteString("  ret void\n")
		case asm.I1:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", t, r0)
			fmt.Fprintf(c.b, "  ret i1 %%%s\n", t)
		case asm.I8:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, r0)
			fmt.Fprintf(c.b, "  ret i8 %%%s\n", t)
		case asm.I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, r0)
			fmt.Fprintf(c.b, "  ret i16 %%%s\n", t)
		case asm.I32:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, r0)
			fmt.Fprintf(c.b, "  ret i32 %%%s\n", t)
		default:
			fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, r0)
		}
		return nil
	}

	// Return from stored result slots when they are explicitly written
	// (or their addresses escape). Otherwise fall back to register returns.
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

	// Aggregate return.
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

func (c *arm64Ctx) lowerRetZero() {
	switch c.sig.Ret {
	case asm.Void:
		c.b.WriteString("  ret void\n")
	case asm.I32:
		c.b.WriteString("  ret i32 0\n")
	default:
		fmt.Fprintf(c.b, "  ret %s 0\n", c.sig.Ret)
	}
}

func IsTarget(triple string) bool {
	arch, _, _ := strings.Cut(strings.ToLower(triple), "-")
	return arch == "aarch64" || arch == "arm64" || arch == "arm64e" || arch == "aarch64_be"
}
