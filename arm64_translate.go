package plan9asm

import (
	"fmt"
	"strings"
)

type arm64EmitBr func(target string)
type arm64EmitCondBr func(cond string, target string, fall string) error

func emitARM64Prelude(b *strings.Builder) {
	b.WriteString("declare i64 @syscall(i64, i64, i64, i64, i64, i64, i64)\n")
	b.WriteString("declare i32 @cliteErrno()\n")
	b.WriteString("declare i64 @llvm.bitreverse.i64(i64)\n")
	b.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\n")
	b.WriteString("declare i64 @llvm.bswap.i64(i64)\n")
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

func translateFuncARM64(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotateSource bool) error {
	fmt.Fprintf(b, "define %s %s(", sig.Ret, llvmGlobal(sig.Name))
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
	emitBr := func(target string) {
		fmt.Fprintf(c.b, "  br label %%%s\n", arm64LLVMBlockName(target))
	}
	emitCondBr := func(cond string, target string, fall string) error {
		cv, err := c.condValue(cond)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", cv, arm64LLVMBlockName(target), arm64LLVMBlockName(fall))
		return nil
	}

	for bi := 0; bi < len(c.blocks); bi++ {
		blk := c.blocks[bi]
		if bi != 0 {
			fmt.Fprintf(c.b, "\n%s:\n", arm64LLVMBlockName(blk.name))
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
		// Fallthrough to next block.
		if bi+1 < len(c.blocks) {
			emitBr(c.blocks[bi+1].name)
			continue
		}
		// Last block: implicit return zero.
		c.lowerRetZero()
	}
	return nil
}

func (c *arm64Ctx) lowerInstr(bi int, ins Instr, emitBr arm64EmitBr, emitCondBr arm64EmitCondBr) (terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	postInc := strings.Contains(rawOp, ".P")
	baseOp := rawOp
	if dot := strings.IndexByte(baseOp, '.'); dot >= 0 {
		baseOp = baseOp[:dot]
	}
	op := Op(baseOp)
	if strings.HasPrefix(rawOp, "SAVE_R19_TO_R28(") ||
		strings.HasPrefix(rawOp, "RESTORE_R19_TO_R28(") ||
		strings.HasPrefix(rawOp, "SAVE_F8_TO_F15(") ||
		strings.HasPrefix(rawOp, "RESTORE_F8_TO_F15(") {
		return false, nil
	}

	switch op {
	case OpTEXT, OpBYTE:
		return false, nil
	case OpRET:
		return true, c.lowerRET()
	case "WORD":
		return false, c.lowerRawWord(ins)
	case "PCALIGN", "NO_LOCAL_POINTERS", "PCDATA", "FUNCDATA", "DMB", "DSB", "ISB", "DC", "PRFM",
		"BREAK", "BRK", "UNDEF", "#UNDEF", "YIELD", "NOP",
		"FLDPD", "FSTPD", "FMOVS", "STY",
		"P256ADDINLINE", "P256MULBY2INLINE", "MOV", "CCMP",
		"#IFDEF", "#ELSE", "#ENDIF":
		return false, nil
	}

	if ok, term, err := c.lowerData(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomic(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVec(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFP(op, ins); ok {
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
	return false, fmt.Errorf("arm64: unsupported instruction %s", ins.Op)
}

func (c *arm64Ctx) lowerRET() error {
	// Prefer classic Go asm return slots if present; many stdlib asm functions
	// never materialize the return value in R0 and only store to ret+off(FP).
	if len(c.fpResults) == 0 {
		r0, err := c.loadReg(Reg("R0"))
		if err != nil {
			return err
		}
		switch c.sig.Ret {
		case Void:
			c.b.WriteString("  ret void\n")
		case I1:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", t, r0)
			fmt.Fprintf(c.b, "  ret i1 %%%s\n", t)
		case I8:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, r0)
			fmt.Fprintf(c.b, "  ret i8 %%%s\n", t)
		case I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, r0)
			fmt.Fprintf(c.b, "  ret i16 %%%s\n", t)
		case I32:
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
	case Void:
		c.b.WriteString("  ret void\n")
	case I32:
		c.b.WriteString("  ret i32 0\n")
	default:
		fmt.Fprintf(c.b, "  ret %s 0\n", c.sig.Ret)
	}
}
