package plan9asm

import (
	"fmt"
	"sort"
	"strings"
)

type armCtx struct {
	b        *strings.Builder
	sig      FuncSig
	resolve  func(string) string
	sigs     map[string]FuncSig
	annotate bool

	tmp int

	blocks []armBlock

	usedRegs  map[Reg]bool
	regSlot   map[Reg]string
	usedFRegs map[Reg]bool
	fRegSlot  map[Reg]string

	flagsNSlot   string
	flagsZSlot   string
	flagsCSlot   string
	flagsVSlot   string
	flagsWritten bool

	exclusiveValidSlot string
	exclusivePtrSlot   string
	exclusiveSizeSlot  string
	exclusiveValueSlot string

	fpParams       map[int64]FrameSlot
	fpParamAlloca  map[int64]string
	fpResults      []FrameSlot
	fpResAllocaOff map[int64]string
	fpResAllocaIdx map[int]string
	fpResWritten   map[int]bool
	fpResAddrTaken map[int]bool
}

func newARMCtx(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotate bool) *armCtx {
	c := &armCtx{
		b:              b,
		sig:            sig,
		resolve:        resolve,
		sigs:           sigs,
		annotate:       annotate,
		blocks:         armSplitBlocks(fn),
		usedRegs:       map[Reg]bool{},
		regSlot:        map[Reg]string{},
		usedFRegs:      map[Reg]bool{},
		fRegSlot:       map[Reg]string{},
		fpParams:       map[int64]FrameSlot{},
		fpParamAlloca:  map[int64]string{},
		fpResAllocaOff: map[int64]string{},
		fpResAllocaIdx: map[int]string{},
		fpResWritten:   map[int]bool{},
		fpResAddrTaken: map[int]bool{},
	}
	for _, s := range sig.Frame.Params {
		c.fpParams[s.Offset] = s
	}
	c.fpResults = append([]FrameSlot(nil), sig.Frame.Results...)
	return c
}

func (c *armCtx) emitSourceComment(ins Instr) {
	if !c.annotate {
		return
	}
	emitIRSourceComment(c.b, ins.Raw)
}

func (c *armCtx) newTmp() string {
	c.tmp++
	return fmt.Sprintf("t%d", c.tmp)
}

func (c *armCtx) slotName(r Reg) string {
	return "%" + armLLVMBlockName("reg_"+string(r))
}

func (c *armCtx) scanUsedRegs() {
	isFReg := func(r Reg) bool {
		return strings.HasPrefix(string(r), "F")
	}
	markReg := func(r Reg) {
		if r == "" {
			return
		}
		if isFReg(r) {
			c.usedFRegs[r] = true
		} else {
			c.usedRegs[r] = true
		}
	}
	markOp := func(op Operand) {
		switch op.Kind {
		case OpReg, OpRegShift:
			markReg(op.Reg)
			markReg(op.ShiftReg)
		case OpMem:
			markReg(op.Mem.Base)
			markReg(op.Mem.Index)
			if shift, ok := armMemoryShift(op.Mem); ok {
				markReg(shift.Reg)
				markReg(shift.ShiftReg)
			}
		case OpRegList:
			for _, r := range op.RegList {
				markReg(r)
			}
		}
	}
	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			if ins.Op == OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
				if structure, ok := decodeARMRawNEONStructureFourMultiple(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", structure.base)))
					if structure.offset != 13 && structure.offset != 15 {
						markReg(Reg(fmt.Sprintf("R%d", structure.offset)))
					}
					for index := 0; index < 4; index++ {
						markReg(armRawVFPBackingReg(structure.first+index*structure.stride, 64))
					}
				}
				if immediate, ok := decodeARMRawNEONModifiedImmediate(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(immediate.destination, 64))
					if immediate.quad {
						markReg(armRawVFPBackingReg(immediate.destination+1, 64))
					}
				}
				if move, ok := decodeARMRawNEONCoreLaneMove(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", move.core)))
					markReg(armRawVFPBackingReg(move.vector, 64))
				}
				if structure, ok := decodeARMRawNEONStructureOneLane(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", structure.base)))
					if structure.offset != 13 && structure.offset != 15 {
						markReg(Reg(fmt.Sprintf("R%d", structure.offset)))
					}
					markReg(armRawVFPBackingReg(structure.first, 64))
				}
				if structure, ok := decodeARMRawNEONStructureFourLane(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", structure.base)))
					if structure.offset != 13 && structure.offset != 15 {
						markReg(Reg(fmt.Sprintf("R%d", structure.offset)))
					}
					for index := 0; index < 4; index++ {
						markReg(armRawVFPBackingReg(structure.first+index*structure.stride, 64))
					}
				}
				if transpose, ok := decodeARMRawNEONTranspose(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(transpose.first, 64))
					markReg(armRawVFPBackingReg(transpose.second, 64))
					if transpose.quad {
						markReg(armRawVFPBackingReg(transpose.first+1, 64))
						markReg(armRawVFPBackingReg(transpose.second+1, 64))
					}
				}
				if narrow, ok := decodeARMRawNEONShiftRightNarrow(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(narrow.source, 64))
					markReg(armRawVFPBackingReg(narrow.source+1, 64))
					markReg(armRawVFPBackingReg(narrow.destination, 64))
				}
				if clear, ok := decodeARMRawNEONBitClearImmediate(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(clear.destination, 64))
					if clear.quad {
						markReg(armRawVFPBackingReg(clear.destination+1, 64))
					}
				}
				if extract, ok := decodeARMRawNEONExtract(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(extract.lhs, 64))
					markReg(armRawVFPBackingReg(extract.rhs, 64))
					markReg(armRawVFPBackingReg(extract.destination, 64))
					if extract.quad {
						markReg(armRawVFPBackingReg(extract.lhs+1, 64))
						markReg(armRawVFPBackingReg(extract.rhs+1, 64))
						markReg(armRawVFPBackingReg(extract.destination+1, 64))
					}
				}
				if narrow, ok := decodeARMRawNEONMoveNarrow(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(narrow.source, 64))
					markReg(armRawVFPBackingReg(narrow.source+1, 64))
					markReg(armRawVFPBackingReg(narrow.destination, 64))
				}
				if insert, ok := decodeARMRawNEONShiftInsert(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(insert.source, 64))
					markReg(armRawVFPBackingReg(insert.destination, 64))
					if insert.quad {
						markReg(armRawVFPBackingReg(insert.source+1, 64))
						markReg(armRawVFPBackingReg(insert.destination+1, 64))
					}
				}
				if shift, ok := decodeARMRawNEONShiftRightImmediate(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(shift.source, 64))
					markReg(armRawVFPBackingReg(shift.destination, 64))
					if shift.quad {
						markReg(armRawVFPBackingReg(shift.source+1, 64))
						markReg(armRawVFPBackingReg(shift.destination+1, 64))
					}
				}
				if reverse, ok := decodeARMRawNEONReverse(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(reverse.source, 64))
					markReg(armRawVFPBackingReg(reverse.destination, 64))
					if reverse.quad {
						markReg(armRawVFPBackingReg(reverse.source+1, 64))
						markReg(armRawVFPBackingReg(reverse.destination+1, 64))
					}
				}
				if multiply, ok := decodeARMRawNEONMultiplyLongLane(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(multiply.lhs, 64))
					markReg(armRawVFPBackingReg(multiply.scalar, 64))
					markReg(armRawVFPBackingReg(multiply.destination, 64))
					markReg(armRawVFPBackingReg(multiply.destination+1, 64))
				}
				if multiply, ok := decodeARMRawNEONMultiplyLongVector(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(multiply.lhs, 64))
					markReg(armRawVFPBackingReg(multiply.rhs, 64))
					markReg(armRawVFPBackingReg(multiply.destination, 64))
					markReg(armRawVFPBackingReg(multiply.destination+1, 64))
				}
				if arithmetic, ok := decodeARMRawNEONAddSub(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(arithmetic.lhs, 64))
					markReg(armRawVFPBackingReg(arithmetic.rhs, 64))
					markReg(armRawVFPBackingReg(arithmetic.destination, 64))
					if arithmetic.quad {
						markReg(armRawVFPBackingReg(arithmetic.lhs+1, 64))
						markReg(armRawVFPBackingReg(arithmetic.rhs+1, 64))
						markReg(armRawVFPBackingReg(arithmetic.destination+1, 64))
					}
				}
				if transfer, ok := decodeARMRawVFPLoadStore(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", transfer.base)))
					markReg(armRawVFPBackingReg(transfer.register, transfer.bits))
				}
				if shift, ok := decodeARMRawNEONShiftImmediate(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(shift.source, 64))
					markReg(armRawVFPBackingReg(shift.destination, 64))
					if shift.quad {
						markReg(armRawVFPBackingReg(shift.source+1, 64))
						markReg(armRawVFPBackingReg(shift.destination+1, 64))
					}
				}
				if move, ok := decodeARMRawVFPMove(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(move.source, move.bits))
					markReg(armRawVFPBackingReg(move.destination, move.bits))
				}
				if pairwise, ok := decodeARMRawNEONPairwiseMinMax(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(pairwise.lhs, 64))
					markReg(armRawVFPBackingReg(pairwise.rhs, 64))
					markReg(armRawVFPBackingReg(pairwise.destination, 64))
				}
				if minmax, ok := decodeARMRawNEONMinMax(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(minmax.lhs, 64))
					markReg(armRawVFPBackingReg(minmax.rhs, 64))
					markReg(armRawVFPBackingReg(minmax.destination, 64))
					if minmax.quad {
						markReg(armRawVFPBackingReg(minmax.lhs+1, 64))
						markReg(armRawVFPBackingReg(minmax.rhs+1, 64))
						markReg(armRawVFPBackingReg(minmax.destination+1, 64))
					}
				}
				if status, ok := decodeARMRawVFPStatusTransfer(uint32(ins.Args[0].Imm)); ok && !status.toFlags {
					markReg(Reg(fmt.Sprintf("R%d", status.core)))
				}
				if arithmetic, ok := decodeARMRawVFPScalarArithmetic(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(arithmetic.lhs, arithmetic.bits))
					markReg(armRawVFPBackingReg(arithmetic.rhs, arithmetic.bits))
					markReg(armRawVFPBackingReg(arithmetic.destination, arithmetic.bits))
				}
				if multiply, ok := decodeARMRawNEONMultiplyLane(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(multiply.scalar, 64))
					markReg(armRawVFPBackingReg(multiply.lhs, 64))
					markReg(armRawVFPBackingReg(multiply.destination, 64))
					if multiply.quad {
						markReg(armRawVFPBackingReg(multiply.lhs+1, 64))
						markReg(armRawVFPBackingReg(multiply.destination+1, 64))
					}
				}
				if conversion, ok := decodeARMRawNEONConvertFloat32(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(conversion.source, 64))
					markReg(armRawVFPBackingReg(conversion.destination, 64))
					if conversion.quad {
						markReg(armRawVFPBackingReg(conversion.source+1, 64))
						markReg(armRawVFPBackingReg(conversion.destination+1, 64))
					}
				}
				if moveLong, ok := decodeARMRawNEONMoveLong(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(moveLong.source, 64))
					markReg(armRawVFPBackingReg(moveLong.destination, 64))
					markReg(armRawVFPBackingReg(moveLong.destination+1, 64))
				}
				if widening, ok := decodeARMRawNEONWideningAddSub(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(widening.lhs, 64))
					markReg(armRawVFPBackingReg(widening.rhs, 64))
					markReg(armRawVFPBackingReg(widening.destination, 64))
					markReg(armRawVFPBackingReg(widening.destination+1, 64))
				}
				if duplicate, ok := decodeARMRawNEONDup(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", duplicate.core)))
					markReg(armRawVFPBackingReg(duplicate.destination, 64))
					if duplicate.quad {
						markReg(armRawVFPBackingReg(duplicate.destination+1, 64))
					}
				}
				if immediate, ok := decodeARMRawVFPImmediate(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(immediate.destination, immediate.bits))
				}
				if decoded, err := decodeARMRawWordInstruction(ins); err == nil {
					for _, op := range decoded.Args {
						markOp(op)
						if single, ok := armSingleOperandNumber(op); ok {
							markReg(armRawVFPBackingReg(single, 32))
						}
					}
				}
				if compare, ok := decodeARMRawVFPCompare(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(compare.lhs, compare.bits))
					if !compare.zeroRHS {
						markReg(armRawVFPBackingReg(compare.rhs, compare.bits))
					}
				}
				if pair, ok := decodeARMRawVMOVPair(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", pair.firstCore)))
					markReg(Reg(fmt.Sprintf("R%d", pair.secondCore)))
					if pair.double {
						markReg(armRawVFPBackingReg(pair.firstDouble, 64))
					} else {
						markReg(armRawVFPBackingReg(pair.firstSingle, 32))
						markReg(armRawVFPBackingReg(pair.firstSingle+1, 32))
					}
				}
				if multiple, ok := decodeARMRawVFPMultiple(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", multiple.base)))
					for register := multiple.first; register < multiple.first+multiple.count; register++ {
						markReg(armRawVFPBackingReg(register, multiple.bits))
					}
				}
				if structure, ok := decodeARMRawNEONStructureOne(uint32(ins.Args[0].Imm)); ok {
					markReg(Reg(fmt.Sprintf("R%d", structure.base)))
					if structure.offset != 13 && structure.offset != 15 {
						markReg(Reg(fmt.Sprintf("R%d", structure.offset)))
					}
					for register := structure.first; register < structure.first+structure.count; register++ {
						markReg(armRawVFPBackingReg(register, 64))
					}
				}
				if logical, ok := decodeARMRawNEONBitwise(uint32(ins.Args[0].Imm)); ok {
					markReg(armRawVFPBackingReg(logical.lhs, 64))
					markReg(armRawVFPBackingReg(logical.rhs, 64))
					markReg(armRawVFPBackingReg(logical.destination, 64))
					if logical.quad {
						markReg(armRawVFPBackingReg(logical.lhs+1, 64))
						markReg(armRawVFPBackingReg(logical.rhs+1, 64))
						markReg(armRawVFPBackingReg(logical.destination+1, 64))
					}
				}
			}
			for _, op := range ins.Args {
				markOp(op)
			}
		}
	}
	if len(c.sig.ArgRegs) > 0 {
		for i := 0; i < len(c.sig.Args) && i < len(c.sig.ArgRegs); i++ {
			markReg(c.sig.ArgRegs[i])
		}
	} else {
		for i := 0; i < len(c.sig.Args) && i < 4; i++ {
			markReg(Reg(fmt.Sprintf("R%d", i)))
		}
	}
	for i := 0; i <= 15; i++ {
		markReg(Reg(fmt.Sprintf("R%d", i)))
	}
	markReg(SP)
}

func (c *armCtx) emitEntryAllocasAndArgInit() error {
	c.scanUsedRegs()
	regs := make([]string, 0, len(c.usedRegs))
	for r := range c.usedRegs {
		regs = append(regs, string(r))
	}
	sort.Strings(regs)

	c.b.WriteString(armLLVMBlockName("entry") + ":\n")
	for _, rs := range regs {
		r := Reg(rs)
		slot := c.slotName(r)
		c.regSlot[r] = slot
		fmt.Fprintf(c.b, "  %s = alloca i32\n", slot)
		fmt.Fprintf(c.b, "  store i32 0, ptr %s\n", slot)
	}
	fregs := make([]string, 0, len(c.usedFRegs))
	for r := range c.usedFRegs {
		fregs = append(fregs, string(r))
	}
	sort.Strings(fregs)
	for _, rs := range fregs {
		r := Reg(rs)
		slot := "%" + armLLVMBlockName("freg_"+string(r))
		c.fRegSlot[r] = slot
		fmt.Fprintf(c.b, "  %s = alloca i64\n", slot)
		fmt.Fprintf(c.b, "  store i64 0, ptr %s\n", slot)
	}

	c.flagsNSlot = "%flags_n"
	c.flagsZSlot = "%flags_z"
	c.flagsCSlot = "%flags_c"
	c.flagsVSlot = "%flags_v"
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsNSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsNSlot)
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsZSlot)
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsCSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCSlot)
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsVSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsVSlot)

	c.exclusiveValidSlot = "%exclusive_valid"
	c.exclusivePtrSlot = "%exclusive_ptr"
	c.exclusiveSizeSlot = "%exclusive_size"
	c.exclusiveValueSlot = "%exclusive_value"
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.exclusiveValidSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.exclusiveValidSlot)
	fmt.Fprintf(c.b, "  %s = alloca ptr\n", c.exclusivePtrSlot)
	fmt.Fprintf(c.b, "  store ptr null, ptr %s\n", c.exclusivePtrSlot)
	fmt.Fprintf(c.b, "  %s = alloca i8\n", c.exclusiveSizeSlot)
	fmt.Fprintf(c.b, "  store i8 0, ptr %s\n", c.exclusiveSizeSlot)
	fmt.Fprintf(c.b, "  %s = alloca i64\n", c.exclusiveValueSlot)
	fmt.Fprintf(c.b, "  store i64 0, ptr %s\n", c.exclusiveValueSlot)

	for _, p := range c.sig.Frame.Params {
		if p.Index < 0 || p.Index >= len(c.sig.Args) {
			return fmt.Errorf("arm: FP param slot +%d(FP) invalid arg index %d", p.Offset, p.Index)
		}
		value := fmt.Sprintf("%%arg%d", p.Index)
		if fields := frameSlotFields(p); len(fields) != 0 {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s%s\n", extracted, c.sig.Args[p.Index], value, frameSlotExtractSuffix(p))
			value = "%" + extracted
		}
		name := fmt.Sprintf("%%fp_arg_%d", p.Offset)
		c.fpParamAlloca[p.Offset] = name
		fmt.Fprintf(c.b, "  %s = alloca %s\n", name, p.Type)
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", p.Type, value, name)
	}

	for _, r := range c.fpResults {
		name := fmt.Sprintf("%%fp_ret_%d", r.Index)
		c.fpResAllocaIdx[r.Index] = name
		c.fpResAllocaOff[r.Offset] = name
		fmt.Fprintf(c.b, "  %s = alloca %s\n", name, r.Type)
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", r.Type, llvmZeroValue(r.Type), name)
	}

	if len(c.sig.ArgRegs) > 0 {
		for i := 0; i < len(c.sig.Args) && i < len(c.sig.ArgRegs); i++ {
			slot, ok := c.regSlot[c.sig.ArgRegs[i]]
			if !ok {
				continue
			}
			v, ok, err := armValueAsI32(c, c.sig.Args[i], fmt.Sprintf("%%arg%d", i))
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n", v, slot)
		}
	}
	return nil
}

func armValueAsI32(c *armCtx, ty LLVMType, v string) (out string, ok bool, err error) {
	switch ty {
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, v)
		return "%" + t, true, nil
	case I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", t, v)
		return "%" + t, true, nil
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i32\n", t, v)
		return "%" + t, true, nil
	case I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", t, v)
		return "%" + t, true, nil
	case I32:
		return v, true, nil
	case I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v)
		return "%" + t, true, nil
	default:
		return "", false, nil
	}
}

func (c *armCtx) loadReg(r Reg) (string, error) {
	slot, ok := c.regSlot[r]
	if !ok {
		return "", fmt.Errorf("arm: unknown reg %s", r)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *armCtx) storeReg(r Reg, v string) error {
	slot, ok := c.regSlot[r]
	if !ok {
		return fmt.Errorf("arm: unknown reg %s", r)
	}
	fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n", v, slot)
	return nil
}

func (c *armCtx) loadFReg(r Reg) (string, error) {
	slot, ok := c.fRegSlot[r]
	if !ok {
		return "", fmt.Errorf("arm: unknown freg %s", r)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *armCtx) storeFReg(r Reg, v string) error {
	slot, ok := c.fRegSlot[r]
	if !ok {
		return fmt.Errorf("arm: unknown freg %s", r)
	}
	fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
	return nil
}

func (c *armCtx) ptrFromSB(sym string) (string, error) {
	base, off, ok := parseSBRef(sym)
	if !ok {
		return "", fmt.Errorf("invalid (SB) sym ref: %q", sym)
	}
	base = strings.TrimPrefix(base, "$")
	res := base
	if strings.Contains(base, "·") || strings.Contains(base, "/") || strings.Contains(base, ".") {
		res = c.resolve(base)
	} else {
		res = c.resolve("·" + base)
	}
	p := llvmGlobal(res)
	if off == 0 {
		return p, nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i32 %d\n", t, p, off)
	return "%" + t, nil
}
