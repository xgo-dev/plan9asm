package plan9asm

import (
	"fmt"
	"strings"
)

type amd64EmitBr func(target string)
type amd64EmitCondBr func(cond string, target string, fall string) error

func emitAMD64Prelude(b *strings.Builder, goarch string, file *File) {
	b.WriteString("declare i64 @syscall(i64, i64, i64, i64, i64, i64, i64)\n")
	b.WriteString("declare i32 @cliteErrno()\n")
	// Generic LLVM intrinsics used by amd64 lowering.
	b.WriteString("declare i64 @llvm.cttz.i64(i64, i1)\n")
	b.WriteString("declare i32 @llvm.cttz.i32(i32, i1)\n")
	b.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\n")
	b.WriteString("declare i32 @llvm.ctlz.i32(i32, i1)\n")
	b.WriteString("declare i64 @llvm.ctpop.i64(i64)\n")
	b.WriteString("declare i32 @llvm.ctpop.i32(i32)\n")
	b.WriteString("declare i64 @llvm.bswap.i64(i64)\n")
	b.WriteString("declare i32 @llvm.bswap.i32(i32)\n")
	b.WriteString("declare double @llvm.sqrt.f64(double)\n")
	b.WriteString("declare double @llvm.rint.f64(double)\n")
	if goarch == "386" {
		b.WriteString("declare double @llvm.floor.f64(double)\n")
		b.WriteString("declare double @llvm.ceil.f64(double)\n")
		b.WriteString("declare double @llvm.trunc.f64(double)\n")
		b.WriteString("declare double @llvm.fabs.f64(double)\n")
	}
	b.WriteString("declare <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8>, <16 x i8>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesenc(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesenclast(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesdec(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesdeclast(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aeskeygenassist(<2 x i64>, i8 immarg)\n")
	b.WriteString("\n")
	// x86-64 CRC32 (SSE4.2) and PCLMULQDQ intrinsics.
	b.WriteString("declare i64 @llvm.x86.sse42.crc32.64.64(i64, i64)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.crc32.32.32(i32, i32)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.crc32.32.16(i32, i16)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.crc32.32.8(i32, i8)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.pclmulqdq(<2 x i64>, <2 x i64>, i8 immarg)\n")
	// SSE2 helpers used by stdlib asm (e.g. internal/bytealg).
	b.WriteString("declare i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8>)\n")
	b.WriteString("\n")
	b.WriteString("\n")
	if goarch == "386" {
		emit386StringHelpers(b, file)
	}
}

func emit386StringHelpers(b *strings.Builder, file *File) {
	needMOVSB, needMOVSL, needSTOSL, needSCASB := false, false, false, false
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			switch strings.ToUpper(string(ins.Op)) {
			case "MOVSB":
				needMOVSB = true
			case "MOVSL":
				needMOVSL = true
			case "STOSL":
				needSTOSL = true
			case "SCASB":
				needSCASB = true
			}
		}
	}
	if needMOVSB {
		emit386MOVSHelper(b, "__plan9asm_movsb", "i8", 1)
	}
	if needMOVSL {
		emit386MOVSHelper(b, "__plan9asm_movsl", "i32", 4)
	}
	if needSTOSL {
		b.WriteString(`define internal void @__plan9asm_rep_stosl(i64 %addr, i32 %value, i64 %count, i1 %backward) {
entry:
  br label %loop
loop:
  %cur = phi i64 [ %addr, %entry ], [ %next, %body ]
  %left = phi i64 [ %count, %entry ], [ %remaining, %body ]
  %done = icmp eq i64 %left, 0
  br i1 %done, label %exit, label %body
body:
  %ptr = inttoptr i64 %cur to ptr
  store i32 %value, ptr %ptr, align 1
  %step = select i1 %backward, i64 -4, i64 4
  %next = add i64 %cur, %step
  %remaining = sub i64 %left, 1
  br label %loop
exit:
  ret void
}

`)
	}
	if needSCASB {
		b.WriteString(`define internal { i64, i64, i1 } @__plan9asm_repne_scasb(i64 %addr, i8 %needle, i64 %count, i1 %backward) {
entry:
  br label %loop
loop:
  %cur = phi i64 [ %addr, %entry ], [ %next, %miss ]
  %left = phi i64 [ %count, %entry ], [ %remaining, %miss ]
  %empty = icmp eq i64 %left, 0
  br i1 %empty, label %not_found, label %scan
scan:
  %ptr = inttoptr i64 %cur to ptr
  %value = load i8, ptr %ptr, align 1
  %equal = icmp eq i8 %value, %needle
  %step = select i1 %backward, i64 -1, i64 1
  %scan_next = add i64 %cur, %step
  %scan_remaining = sub i64 %left, 1
  br i1 %equal, label %found, label %miss
miss:
  %next = phi i64 [ %scan_next, %scan ]
  %remaining = phi i64 [ %scan_remaining, %scan ]
  br label %loop
found:
  %found0 = insertvalue { i64, i64, i1 } undef, i64 %scan_next, 0
  %found1 = insertvalue { i64, i64, i1 } %found0, i64 %scan_remaining, 1
  %found2 = insertvalue { i64, i64, i1 } %found1, i1 true, 2
  ret { i64, i64, i1 } %found2
not_found:
  %miss0 = insertvalue { i64, i64, i1 } undef, i64 %cur, 0
  %miss1 = insertvalue { i64, i64, i1 } %miss0, i64 %left, 1
  %miss2 = insertvalue { i64, i64, i1 } %miss1, i1 false, 2
  ret { i64, i64, i1 } %miss2
}

`)
	}
}

func emit386MOVSHelper(b *strings.Builder, name, ty string, width int) {
	fmt.Fprintf(b, "define internal void @%s(i64 %%dst, i64 %%src, i64 %%count, i1 %%backward) {\n", name)
	b.WriteString(`entry:
  %step = select i1 %backward, i64 `)
	fmt.Fprintf(b, "-%d, i64 %d\n", width, width)
	b.WriteString(`  br label %loop
loop:
  %cur_dst = phi i64 [ %dst, %entry ], [ %next_dst, %body ]
  %cur_src = phi i64 [ %src, %entry ], [ %next_src, %body ]
  %left = phi i64 [ %count, %entry ], [ %remaining, %body ]
  %done = icmp eq i64 %left, 0
  br i1 %done, label %exit, label %body
body:
  %dst_ptr = inttoptr i64 %cur_dst to ptr
  %src_ptr = inttoptr i64 %cur_src to ptr
`)
	fmt.Fprintf(b, "  %%value = load %s, ptr %%src_ptr, align 1\n", ty)
	fmt.Fprintf(b, "  store %s %%value, ptr %%dst_ptr, align 1\n", ty)
	b.WriteString(`  %next_dst = add i64 %cur_dst, %step
  %next_src = add i64 %cur_src, %step
  %remaining = sub i64 %left, 1
  br label %loop
exit:
  ret void
}

`)
}

func translateFuncAMD64(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotateSource bool) error {
	return translateFuncX86(b, fn, sig, resolve, sigs, "amd64", "", X87Auto, annotateSource)
}

func translateFuncX86(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, goarch, targetTriple string, x87Mode X87Mode, annotateSource bool) error {
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

	c := newX86Ctx(b, fn, sig, resolve, sigs, goarch, targetTriple, annotateSource)
	c.x87Mode = x87Mode
	if err := c.emitEntryAllocas(); err != nil {
		return err
	}
	if err := c.lowerBlocks(); err != nil {
		return err
	}

	b.WriteString("}\n")
	return nil
}

func (c *amd64Ctx) lowerBlocks() error {
	emitBr := func(target string) {
		fmt.Fprintf(c.b, "  br label %%%s\n", amd64LLVMBlockName(target))
	}
	emitCondBr := func(cond string, target string, fall string) error {
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", cond, amd64LLVMBlockName(target), amd64LLVMBlockName(fall))
		return nil
	}

	for bi := 0; bi < len(c.blocks); bi++ {
		blk := c.blocks[bi]
		if bi != 0 {
			fmt.Fprintf(c.b, "\n%s:\n", amd64LLVMBlockName(blk.name))
		}

		terminated := false
		for ii, ins := range blk.instrs {
			c.emitSourceComment(ins)
			term, err := c.lowerInstr(bi, ii, ins, emitBr, emitCondBr)
			if err != nil {
				return fmt.Errorf("%q: %w", ins.Raw, err)
			}
			if term {
				terminated = true
				break
			}
		}
		if terminated {
			continue
		}
		if c.repeatPrefix != "" && bi+1 == len(c.blocks) {
			prefix := c.repeatPrefix
			c.repeatPrefix = ""
			return fmt.Errorf("386 %s prefix has no following string instruction", prefix)
		}
		// Fallthrough.
		if bi+1 < len(c.blocks) {
			emitBr(c.blocks[bi+1].name)
			continue
		}
		c.lowerRetZero()
	}
	return nil
}

func (c *amd64Ctx) lowerInstr(bi int, ii int, ins Instr, emitBr amd64EmitBr, emitCondBr amd64EmitCondBr) (terminated bool, err error) {
	c.allowSPWrite = models386SPWrite(ins)
	defer func() { c.allowSPWrite = false }()
	op := strings.ToUpper(string(ins.Op))
	c.zeroUpperVector = strings.HasPrefix(op, "V")
	if c.repeatPrefix != "" && op != "MOVSB" && op != "MOVSL" && op != "STOSL" && op != "SCASB" {
		prefix := c.repeatPrefix
		c.repeatPrefix = ""
		return false, fmt.Errorf("386 %s prefix is unsupported for %s", prefix, op)
	}
	if strings.HasPrefix(op, "GET_TLS(") {
		// Macro-expanded helper from go_tls.h. Keep current simplified model.
		return false, nil
	}
	switch Op(op) {
	case OpTEXT, OpBYTE, OpWORD:
		return false, nil
	case OpRET:
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, c.tailCallAndRet(ins.Args[0])
		}
		if len(ins.Args) > 1 {
			return true, fmt.Errorf("amd64 RET expects at most 1 operand: %q", ins.Raw)
		}
		return true, c.lowerRET()
	case "PCALIGN", "NO_LOCAL_POINTERS", "PCDATA", "FUNCDATA", "NOP",
		"PUSH_REGS_HOST_TO_ABI0()", "POP_REGS_HOST_TO_ABI0()":
		// Alignment directive emitted by stdlib asm; no semantic effect in our IR.
		return false, nil
	case "ADJSP":
		if c.goarch != "386" {
			return false, nil
		}
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
			return false, fmt.Errorf("386 ADJSP expects an immediate: %q", ins.Raw)
		}
		sp, err := c.loadReg(SP)
		if err != nil {
			return false, err
		}
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %d\n", next, sp, int64(ins.Args[0].Imm))
		return false, c.storeRegUnchecked(SP, "%"+next)
	case "CLD":
		if c.goarch != "386" {
			return false, nil
		}
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("386 CLD takes no operands: %q", ins.Raw)
		}
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.directionSlot)
		return false, nil
	case "STD":
		if c.goarch != "386" {
			return false, nil
		}
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("386 STD takes no operands: %q", ins.Raw)
		}
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.directionSlot)
		return false, nil
	case "REP", "REPN":
		if c.goarch != "386" {
			return false, nil
		}
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		c.repeatPrefix = op
		return false, nil
	}
	if ok, term, err := c.lowerBranch(bi, ii, Op(op), ins, emitBr, emitCondBr); ok {
		return term, err
	}
	if ok, term, err := c.lowerCmpBt(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerX87(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFP(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerCrc32(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVec(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomic(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSyscall(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerString(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMov(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(Op(op), ins); ok {
		return term, err
	}
	return false, fmt.Errorf("amd64: unsupported instruction %s", ins.Op)
}

func (c *amd64Ctx) lowerRET() error {
	// Prefer classic Go asm return slots if present.
	if len(c.fpResults) == 0 {
		rax, err := c.loadReg(AX)
		if err != nil {
			return err
		}
		switch c.sig.Ret {
		case Void:
			c.b.WriteString("  ret void\n")
		case I1:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", t, rax)
			fmt.Fprintf(c.b, "  ret i1 %%%s\n", t)
		case I8:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, rax)
			fmt.Fprintf(c.b, "  ret i8 %%%s\n", t)
		case I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, rax)
			fmt.Fprintf(c.b, "  ret i16 %%%s\n", t)
		case I32:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, rax)
			fmt.Fprintf(c.b, "  ret i32 %%%s\n", t)
		default:
			fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, rax)
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

func (c *amd64Ctx) lowerRetZero() {
	switch c.sig.Ret {
	case Void:
		c.b.WriteString("  ret void\n")
	case I32:
		c.b.WriteString("  ret i32 0\n")
	default:
		fmt.Fprintf(c.b, "  ret %s 0\n", c.sig.Ret)
	}
}
