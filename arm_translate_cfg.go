package plan9asm

import (
	"fmt"
	"strings"
)

func translateFuncARM(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotateSource bool) error {
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
				return fmt.Errorf("%s: %w", ins.Raw, err)
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

func (c *armCtx) lowerInstr(bi int, ins Instr, emitBr armEmitBr, emitCondBr armEmitCondBr) (bool, error) {
	rawOp := strings.ToUpper(string(ins.Op))
	baseOp, cond, postInc, setFlags := armDecodeOp(rawOp)
	switch baseOp {
	case string(OpTEXT):
		return false, nil
	case string(OpBYTE):
		return false, fmt.Errorf("arm BYTE cannot be lowered safely as a partial machine instruction: %q", ins.Raw)
	case string(OpRET):
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
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
	case "CLREX":
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("arm CLREX expects no operands: %q", ins.Raw)
		}
		// Preserve the architectural instruction for LLVM while also clearing
		// the translator's modeled exclusive monitor used by STREX lowering.
		c.b.WriteString("  call void asm sideeffect \"clrex\", \"~{memory}\"()\n")
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
		return false, nil
	case "MOVM":
		if ok, term, err := c.lowerMOVM(rawOp, ins); ok {
			return term, err
		}
		return false, fmt.Errorf("arm: unsupported instruction %s", ins.Op)
	case string(OpWORD):
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
			if form, ok := decodeARMRawNEONStructureFourMultiple(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONStructureFourMultiple(form)
			}
			if form, ok := decodeARMRawNEONModifiedImmediate(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONModifiedImmediate(form)
			}
			if form, ok := decodeARMRawNEONCoreLaneMove(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONCoreLaneMove(form)
			}
			if form, ok := decodeARMRawNEONStructureOneLane(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONStructureLane(form, 1)
			}
			if form, ok := decodeARMRawNEONStructureFourLane(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONStructureFourLane(form)
			}
			if form, ok := decodeARMRawNEONTranspose(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONTranspose(form)
			}
			if form, ok := decodeARMRawNEONShiftRightNarrow(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONShiftRightNarrow(form)
			}
			if form, ok := decodeARMRawNEONBitClearImmediate(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONBitClearImmediate(form)
			}
			if form, ok := decodeARMRawNEONExtract(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONExtract(form)
			}
			if form, ok := decodeARMRawNEONMoveNarrow(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONMoveNarrow(form)
			}
			if form, ok := decodeARMRawNEONShiftInsert(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONShiftInsert(form)
			}
			if form, ok := decodeARMRawNEONShiftRightImmediate(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONShiftRightImmediate(form)
			}
			if form, ok := decodeARMRawNEONReverse(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONReverse(form)
			}
			if form, ok := decodeARMRawNEONMultiplyLongLane(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONMultiplyLongLane(form)
			}
			if form, ok := decodeARMRawNEONMultiplyLongVector(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONMultiplyLongVector(form)
			}
			if form, ok := decodeARMRawNEONAddSub(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONAddSub(form)
			}
			if form, ok := decodeARMRawVFPLoadStore(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawVFPLoadStore(form)
			}
			if form, ok := decodeARMRawNEONShiftImmediate(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONShiftImmediate(form)
			}
			if form, ok := decodeARMRawVFPMove(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawVFPMove(form)
			}
			if form, ok := decodeARMRawNEONPairwiseMinMax(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONPairwiseMinMax(form)
			}
			if form, ok := decodeARMRawNEONMinMax(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONMinMax(form)
			}
			if form, ok := decodeARMRawVFPStatusTransfer(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawVFPStatusTransfer(form)
			}
			if form, ok := decodeARMRawVFPScalarArithmetic(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawVFPScalarArithmetic(form)
			}
			if form, ok := decodeARMRawNEONMultiplyLane(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONMultiplyLane(form)
			}
			if form, ok := decodeARMRawNEONConvertFloat32(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONConvertFloat32(form)
			}
			if form, ok := decodeARMRawNEONMoveLong(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONMoveLong(form)
			}
			if form, ok := decodeARMRawNEONWideningAddSub(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONWideningAddSub(form)
			}
			if form, ok := decodeARMRawNEONDup(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONDup(form)
			}
			if form, ok := decodeARMRawNEONStructureOne(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONStructureOne(form)
			}
			if form, ok := decodeARMRawNEONBitwise(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawNEONBitwise(form)
			}
			if form, ok := decodeARMRawSXTB(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawSXTB(form)
			}
			if form, ok := decodeARMRawVMOVPair(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawVMOVPair(form)
			}
			if form, ok := decodeARMRawVFPMultiple(uint32(ins.Args[0].Imm)); ok {
				return false, c.lowerRawVFPMultiple(form)
			}
		}
		if handled, err := c.lowerRawWord(ins); handled {
			return false, err
		}
		decoded, err := decodeARMRawWordInstruction(ins)
		if err != nil {
			if strings.Contains(err.Error(), "PC-relative") {
				return false, err
			}
			return false, fmt.Errorf("arm WORD cannot be lowered safely because its encoding is unsupported: %q", ins.Raw)
		}
		return c.lowerInstr(bi, decoded, emitBr, emitCondBr)
	case "PCDATA", "FUNCDATA", "NO_LOCAL_POINTERS", "NOP", "DMB", "END", "#IFDEF", "#ELSE", "#ENDIF":
		return false, nil
	}
	if ok, term, err := c.lowerData(baseOp, cond, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPreload(baseOp, cond, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(baseOp, cond, setFlags, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFloat(baseOp, cond, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSaturation(baseOp, cond, ins); ok {
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
		r0, err := c.loadReg(Reg("R0"))
		if err != nil {
			return err
		}
		switch c.sig.Ret {
		case Void:
			c.b.WriteString("  ret void\n")
		case I1, I8, I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", t, r0, c.sig.Ret)
			fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, t)
		case I32:
			fmt.Fprintf(c.b, "  ret i32 %s\n", r0)
		case I64:
			r1, err := c.loadReg(Reg("R1"))
			if err != nil {
				return err
			}
			lo := c.newTmp()
			hi := c.newTmp()
			shifted := c.newTmp()
			joined := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", lo, r0)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", hi, r1)
			fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", shifted, hi)
			fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", joined, lo, shifted)
			fmt.Fprintf(c.b, "  ret i64 %%%s\n", joined)
		case Ptr:
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
	if c.sig.Ret == I64 && len(c.fpResults) == 2 && c.fpResults[0].Type == I32 && c.fpResults[1].Type == I32 {
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
	case Void:
		c.b.WriteString("  ret void\n")
	default:
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, llvmZeroValue(c.sig.Ret))
	}
}
