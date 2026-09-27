package plan9asm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type arm64Ctx struct {
	b        *strings.Builder
	sig      FuncSig
	resolve  func(string) string
	sigs     map[string]FuncSig
	annotate bool

	tmp int

	blocks []arm64Block

	rawDataGlobals map[string]string // local source label -> LLVM global
	rawDataOffsets map[string]int64  // byte offsets for aliases into one pool

	usedRegs map[Reg]bool
	regSlot  map[Reg]string // reg -> alloca name

	usedVRegs      map[int]bool
	vRegSlot       map[int]string // vreg index -> alloca name (<16 x i8>)
	usedZRegs      map[int]bool
	zRegSlot       map[int]string // SVE zreg index -> alloca name (<vscale x 16 x i8>)
	usedPRegs      map[int]bool
	pRegSlot       map[int]string // SVE preg index -> alloca name (<vscale x 16 x i1>)
	usedPNRegs     map[int]bool
	pnRegSlot      map[int]string // SVE predicate-as-counter index -> alloca name (target("aarch64.svcount"))
	localStackSlot string
	localStackSize int64
	dynamicStack   *arm64DynamicStackPlan

	flagsNSlot   string
	flagsZSlot   string
	flagsCSlot   string
	flagsVSlot   string
	flagsWritten bool
	flagFlow     *arm64FlagFlow

	exclusiveValidSlot string
	exclusivePtrSlot   string
	exclusiveSizeSlot  string
	exclusiveValueSlot string

	fpParams       map[int64]FrameSlot // off(FP) -> slot
	fpParamAlloca  map[int64]string    // parameter off(FP) -> mutable alloca
	fpResults      []FrameSlot         // result slots (Index is result index)
	fpResAllocaOff map[int64]string    // off(FP) -> alloca
	fpResAllocaIdx map[int]string      // result index -> alloca
	fpResWritten   map[int]bool        // result index -> direct writes to fp slot
	fpResAddrTaken map[int]bool        // result index -> fp result slot address escaped
}

func newARM64Ctx(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotate bool) *arm64Ctx {
	c := &arm64Ctx{
		b:              b,
		sig:            sig,
		resolve:        resolve,
		sigs:           sigs,
		annotate:       annotate,
		blocks:         arm64SplitBlocks(fn),
		usedRegs:       map[Reg]bool{},
		regSlot:        map[Reg]string{},
		usedVRegs:      map[int]bool{},
		vRegSlot:       map[int]string{},
		usedZRegs:      map[int]bool{},
		zRegSlot:       map[int]string{},
		usedPRegs:      map[int]bool{},
		pRegSlot:       map[int]string{},
		usedPNRegs:     map[int]bool{},
		pnRegSlot:      map[int]string{},
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

func (c *arm64Ctx) emitSourceComment(ins Instr) {
	if !c.annotate {
		return
	}
	emitIRSourceComment(c.b, ins.Raw)
}

func (c *arm64Ctx) newTmp() string {
	c.tmp++
	return fmt.Sprintf("t%d", c.tmp)
}

func (c *arm64Ctx) slotName(r Reg) string {
	// Make the name LLVM-label friendly to keep the IR readable.
	return "%" + arm64LLVMBlockName("reg_"+string(r))
}

func (c *arm64Ctx) vSlotName(idx int) string {
	return fmt.Sprintf("%%v%d", idx)
}

func arm64ParseVReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "V") {
		return 0, false
	}
	// Strip optional lane suffix: V8.D[0], V5.B16, etc.
	if suffix := strings.IndexAny(s, ".["); suffix >= 0 {
		s = s[:suffix]
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "V"))
	if err != nil || n < 0 || n > 31 {
		return 0, false
	}
	return n, true
}

func arm64ParseFReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "F") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "F"))
	if err != nil || n < 0 || n > 31 {
		return 0, false
	}
	return n, true
}

func arm64ParseZReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "Z") {
		return 0, false
	}
	if suffix := strings.IndexAny(s, ".["); suffix >= 0 {
		s = s[:suffix]
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "Z"))
	return n, err == nil && n >= 0 && n <= 31
}

func arm64ParsePReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "P") {
		return 0, false
	}
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		s = s[:dot]
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "P"))
	return n, err == nil && n >= 0 && n <= 15
}

func arm64ParsePNReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "PN") {
		return 0, false
	}
	if suffix := strings.IndexAny(s, ".["); suffix >= 0 {
		s = s[:suffix]
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "PN"))
	return n, err == nil && n >= 0 && n <= 15
}

func (c *arm64Ctx) scanUsedRegs() {
	markReg := func(r Reg) {
		if r == "" {
			return
		}
		if r == Reg("RSP") {
			r = SP
		}
		if idx, ok := arm64ParseZReg(r); ok {
			c.usedZRegs[idx] = true
			return
		}
		if idx, ok := arm64ParsePNReg(r); ok {
			c.usedPNRegs[idx] = true
			return
		}
		if idx, ok := arm64ParsePReg(r); ok {
			c.usedPRegs[idx] = true
			return
		}
		if idx, ok := arm64ParseVReg(r); ok {
			c.usedVRegs[idx] = true
			return
		}
		// ARM64 F registers alias the corresponding 128-bit V registers. Keep a
		// single vector slot so scalar and vector operations observe each
		// other's writes.
		if idx, ok := arm64ParseFReg(r); ok {
			c.usedVRegs[idx] = true
			return
		}
		c.usedRegs[r] = true
	}
	markOp := func(op Operand) {
		switch op.Kind {
		case OpReg:
			markReg(op.Reg)
		case OpMem:
			markReg(op.Mem.Base)
			if op.Mem.Index != "" {
				markReg(op.Mem.Index)
			}
		case OpRegList:
			for _, r := range op.RegList {
				markReg(r)
			}
		}
	}
	markSVEAddForm := func(form arm64RawSVEAdd) {
		markReg(Reg(fmt.Sprintf("Z%d", form.first)))
		if form.mode != arm64SVEAddImmediate {
			markReg(Reg(fmt.Sprintf("Z%d", form.second)))
		}
		if form.mode == arm64SVEAddPredicated {
			markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
		}
		markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
	}

	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			for _, op := range ins.Args {
				markOp(op)
			}
			if ins.Op == OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
				if form, ok := decodeARM64RawSystemRegister(uint32(ins.Args[0].Imm)); ok && form.reg != 31 {
					markReg(Reg(fmt.Sprintf("R%d", form.reg)))
				}
				if form, ok := decodeARM64RawCASP(uint32(ins.Args[0].Imm)); ok {
					for _, reg := range arm64RawCASPRegisterPair(form.expected) {
						markReg(reg)
					}
					for _, reg := range arm64RawCASPRegisterPair(form.newValue) {
						markReg(reg)
					}
					if form.base == 31 {
						markReg(Reg("RSP"))
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
				}
				// Specialized raw decoders below predate the shared Go-table
				// fallback. Also scan the official decoded operands so any
				// instruction handled by that fallback receives register storage.
				if decoded, err := decodeARM64RawWordInstruction(ins); err == nil {
					for _, op := range decoded.Args {
						markOp(op)
					}
				}
				word := uint32(ins.Args[0].Imm)
				if decoded, ok := decodeARM64RawSVECharacterMatch(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEPredicateBreak(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEPredicateIncDec(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEPredicateCount(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEFloatMinMax(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEFloatUnary(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEFloatCompare(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEIntegerCompare(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEPredicateLogical(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEPredicatePermute(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVECompact(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVECopy(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEIntegerUnary(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVERevd(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEStructuredMemory(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEMultiplyAccumulate(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVETernaryBitwise(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEIntegerReduction(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEIntegerDot(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEXAR(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEExtraShift(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVESplice(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEReplicateScalar(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEReplicateBlock(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEContiguousMemory(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEUnsignedLoad(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVESignedLoad(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEAddSubWide(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEMultiplyHigh(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEAddressGeneration(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEFloatDivideScale(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEUnpack(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEAddPairwiseLong(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEIntegerMinMax(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEIntegerMinMaxReduction(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEPTest(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEMOVPRFX(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVEIndex(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if decoded, ok := decodeARM64RawSVELast(word); ok {
					for _, operand := range decoded.Args {
						markOp(operand)
					}
				}
				if form, ok := decodeARM64RawTLBI(word); ok && form.register != ZR {
					markReg(form.register)
				}
				if reg, ok := decodeARM64RawICIVAU(word); ok {
					if reg != ZR {
						markReg(reg)
					}
				}
				if form, ok := decodeARM64RawSVEWhileLO(word); ok {
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("R%d", form.first)))
					markReg(Reg(fmt.Sprintf("R%d", form.second)))
				}
				if form, ok := decodeARM64RawSVELD1B(word); ok {
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("Z%d", form.vector)))
					if form.base == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
					if form.index != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.index)))
					}
				}
				if form, ok := decodeARM64RawStructureLane(word); ok {
					if form.base == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
					if form.post && form.postRegister != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.postRegister)))
					}
					for i := 0; i < form.count; i++ {
						markReg(Reg(fmt.Sprintf("V%d", (form.firstRegister+i)%32)))
					}
				}
				if form, ok := decodeARM64RawAES(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawSM4(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawRDMA(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarADDP(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawDotProduct(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.left)))
					markReg(Reg(fmt.Sprintf("V%d", form.right)))
				}
				if form, ok := decodeARM64RawBFloatDot(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.left)))
					markReg(Reg(fmt.Sprintf("V%d", form.right)))
				}
				if form, ok := decodeARM64RawBFloatMatrix(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.left)))
					markReg(Reg(fmt.Sprintf("V%d", form.right)))
				}
				if form, ok := decodeARM64RawMatrixMultiply(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.left)))
					markReg(Reg(fmt.Sprintf("V%d", form.right)))
				}
				if form, ok := decodeARM64RawFloatMultiplyLong(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawVectorFloatNarrow(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawVectorFloatWiden(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFADDP(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					if !form.scalar {
						markReg(Reg(fmt.Sprintf("V%d", form.second)))
					}
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFloatPairwiseMinMax(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					if !form.scalar {
						markReg(Reg(fmt.Sprintf("V%d", form.second)))
					}
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawTableLookup(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.index)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					for i := 0; i < form.tableCount; i++ {
						markReg(Reg(fmt.Sprintf("V%d", (form.firstTable+i)%32)))
					}
				}
				if form, ok := decodeARM64RawSQDMULH(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawMUL(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawHalvingAddSub(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawIntegerCompare(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					if !form.zero {
						markReg(Reg(fmt.Sprintf("V%d", form.second)))
					}
				}
				if form, ok := decodeARM64RawMLS(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawPairwiseAddLong(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.sourceReg)))
					markReg(Reg(fmt.Sprintf("V%d", form.destReg)))
				}
				if form, ok := decodeARM64RawUMULL(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destReg)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawAddHighNarrow(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawUZP(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawSSHR(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawUSHLL(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawLDnR(word); ok {
					for i := 0; i < form.count; i++ {
						markReg(Reg(fmt.Sprintf("V%d", (form.firstRegister+i)%32)))
					}
					if form.base == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
					if form.post && form.postRegister != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.postRegister)))
					}
				}
				if form, ok := decodeARM64RawUMLAL(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destReg)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawDUPElement(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawMLA(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawCVTF(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawSMEOuterProduct(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.first)))
					markReg(Reg(fmt.Sprintf("Z%d", form.second)))
					markReg(Reg(fmt.Sprintf("P%d", form.firstPred)))
					markReg(Reg(fmt.Sprintf("P%d", form.secondPred)))
				}
				if form, ok := decodeARM64RawSMETileRead(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("R%d", form.row)))
				}
				if form, ok := decodeARM64RawSMETileWrite(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("R%d", form.row)))
				}
				if form, ok := decodeARM64RawSMETileMemory(word); ok {
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("R%d", form.row)))
					if form.base == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
					if form.offset != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.offset)))
					}
				}
				if decoded, ok := decodeARM64RawSVEFloatImmediate(word); ok {
					if destination, _, ok := arm64SVEFloatElementReg(decoded.Args[len(decoded.Args)-1]); ok {
						markReg(Reg(fmt.Sprintf("Z%d", destination)))
					}
					if decoded.Op == "ZFCPY" {
						predicate, _ := arm64ParseSVEPredicateMode(decoded.Args[1], "M", 15)
						markReg(Reg(fmt.Sprintf("P%d", predicate)))
					}
				}
				if decoded, ok := decodeARM64RawSVEDupM(word); ok {
					if destination, _, ok := arm64ParseSVEZElementReg(decoded.Args[1]); ok {
						markReg(Reg(fmt.Sprintf("Z%d", destination)))
					}
				}
				if decoded, ok := decodeARM64RawSVEFloatMultiplyAccumulate(word); ok {
					for _, operand := range decoded.Args {
						if reg, _, ok := arm64ParseSVEZElementReg(operand); ok {
							markReg(Reg(fmt.Sprintf("Z%d", reg)))
						}
						if reg, ok := arm64ParseSVEPredicateMode(operand, "M", 7); ok {
							markReg(Reg(fmt.Sprintf("P%d", reg)))
						}
					}
				}
				if decoded, ok := decodeARM64RawSVEConvert(word); ok {
					if source, _, ok := arm64ParseSVEZElementReg(decoded.Args[0]); ok {
						markReg(Reg(fmt.Sprintf("Z%d", source)))
					}
					if predicate, ok := arm64ParseSVEPredicateMode(decoded.Args[1], "M", 7); ok {
						markReg(Reg(fmt.Sprintf("P%d", predicate)))
					} else if predicate, ok := arm64ParseSVEPredicateMode(decoded.Args[1], "Z", 7); ok {
						markReg(Reg(fmt.Sprintf("P%d", predicate)))
					}
					if destination, _, ok := arm64ParseSVEZElementReg(decoded.Args[2]); ok {
						markReg(Reg(fmt.Sprintf("Z%d", destination)))
					}
				}
				if form, ok := decodeARM64RawFMLA(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.elementReg)))
					markReg(Reg(fmt.Sprintf("V%d", form.sourceReg)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawHalfFMA(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					markReg(Reg(fmt.Sprintf("V%d", form.addend)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFMULByElement(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.elementReg)))
					markReg(Reg(fmt.Sprintf("V%d", form.sourceReg)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarHalfUnary(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarVectorFCVTZ(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarFloatBinary(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarFloatCompare(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					if !form.zero {
						markReg(Reg(fmt.Sprintf("V%d", form.second)))
					}
				}
				if form, ok := decodeARM64RawScalarFloatSelect(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarFloatImmediate(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarIntToFloat(word); ok {
					if form.source != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.source)))
					}
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFixedIntToFloat(word); ok {
					if form.vectorSource {
						markReg(Reg(fmt.Sprintf("V%d", form.source)))
					} else if form.source != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.source)))
					}
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFloatGPMove(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.floatReg)))
					if form.gpReg != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.gpReg)))
					}
				}
				if form, ok := decodeARM64RawBFloatConvert(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawSHA3(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					if form.kind == arm64RawSHA3EOR3 || form.kind == arm64RawSHA3BCAX {
						markReg(Reg(fmt.Sprintf("V%d", form.third)))
					}
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFloatBinary(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
				}
				if form, ok := decodeARM64RawReciprocalEstimate(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					if form.binary {
						markReg(Reg(fmt.Sprintf("V%d", form.second)))
					}
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFSQRT(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFloatAbsNeg(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFloatMinMaxAcross(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFloatCompare(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					if !form.zero {
						markReg(Reg(fmt.Sprintf("V%d", form.second)))
					}
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawLogical(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.first)))
					markReg(Reg(fmt.Sprintf("V%d", form.second)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawFloatImmediate(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawModifiedImmediate(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawScalarFCVTToInt(word); ok {
					markReg(Reg(fmt.Sprintf("F%d", form.source)))
					if form.destination != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.destination)))
					}
				}
				if form, ok := decodeARM64RawFCVTZ(word); ok {
					markReg(Reg(fmt.Sprintf("V%d", form.source)))
					markReg(Reg(fmt.Sprintf("V%d", form.destination)))
				}
				if form, ok := decodeARM64RawMoveWide(word); ok && form.destination != 31 {
					markReg(Reg(fmt.Sprintf("R%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEAddress(word); ok {
					if form.op != "RDVL" {
						if form.source == 31 {
							markReg(SP)
						} else {
							markReg(Reg(fmt.Sprintf("R%d", form.source)))
						}
					}
					if form.destination == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.destination)))
					}
				}
				if form, ok := decodeARM64RawSVECnt(word); ok {
					if form.vector {
						markReg(Reg(fmt.Sprintf("Z%d.%c", form.destination, map[int]byte{16: 'H', 32: 'S', 64: 'D'}[form.elementBits])))
					} else if form.destination != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.destination)))
					}
				}
				if form, ok := decodeARM64RawBitfield(word); ok {
					if form.source != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.source)))
					}
					if form.destination != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.destination)))
					}
				}
				if form, ok := decodeARM64RawSVEPTrue(word); ok {
					markReg(Reg(fmt.Sprintf("P%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVELDST1D(word); ok {
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("Z%d", form.vector)))
					if form.base == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
					if form.registerOffset && form.index != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.index)))
					}
				}
				if form, ok := decodeARM64RawSVELDST1W(word); ok {
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("Z%d", form.vector)))
					if form.base == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
					if form.registerOffset && form.index != 31 {
						markReg(Reg(fmt.Sprintf("R%d", form.index)))
					}
				}
				if reduction, ok := decodeARM64RawSVEFloatMinMaxReduction(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", reduction.form.first)))
					markReg(Reg(fmt.Sprintf("P%d", reduction.form.predicate)))
					markReg(reduction.destination)
				}
				if reduction, ok := decodeARM64RawSVEIntegerAddReduction(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", reduction.form.source)))
					markReg(Reg(fmt.Sprintf("P%d", reduction.form.predicate)))
					markReg(reduction.destination)
				}
				if form, ok := decodeARM64RawSVEFloat(word); ok {
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					switch form.kind {
					case arm64RawSVEFloatFADDV, arm64RawSVEFloatFADDA:
						markReg(Reg(fmt.Sprintf("F%d", form.destination)))
						markReg(Reg(fmt.Sprintf("Z%d", form.first)))
					default:
						markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
						markReg(Reg(fmt.Sprintf("Z%d", form.first)))
						if form.second != form.first {
							markReg(Reg(fmt.Sprintf("Z%d", form.second)))
						}
					}
				}
				if form, ok := decodeARM64RawSVELoadStore(word); ok {
					if form.predicate {
						markReg(Reg(fmt.Sprintf("P%d", form.vector)))
					} else {
						markReg(Reg(fmt.Sprintf("Z%d", form.vector)))
					}
					if form.base == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.base)))
					}
				}
				if form, ok := decodeARM64RawSVEDupImmediate(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEDupGeneral(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
					if form.source == 31 {
						markReg(SP)
					} else {
						markReg(Reg(fmt.Sprintf("R%d", form.source)))
					}
				}
				if form, ok := decodeARM64RawSVEDupElement(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.source)))
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEAdd(word); ok {
					markSVEAddForm(form)
				}
				if _, form, ok := decodeARM64RawSVEAddSub(word); ok {
					markSVEAddForm(form)
				}
				if form, ok := decodeARM64RawSVEShift(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.source)))
					if form.mode == arm64SVELSRWidePredicated || form.mode == arm64SVELSRWideUnpredicated || form.mode == arm64SVELSRVectorPredicated {
						markReg(Reg(fmt.Sprintf("Z%d", form.shifts)))
					}
					if form.mode == arm64SVELSRWidePredicated || form.mode == arm64SVELSRVectorPredicated || form.mode == arm64SVELSRImmediatePredicated {
						markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					}
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVESelect(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.falseValue)))
					markReg(Reg(fmt.Sprintf("Z%d", form.trueValue)))
					markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEMultiply(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.first)))
					switch form.mode {
					case arm64SVEMultiplyPredicated:
						markReg(Reg(fmt.Sprintf("Z%d", form.second)))
						markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					case arm64SVEMultiplyUnpredicated:
						markReg(Reg(fmt.Sprintf("Z%d", form.second)))
					case arm64SVEMultiplyLane:
						markReg(Reg(fmt.Sprintf("Z%d", form.laneVector)))
					}
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEEOR(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.first)))
					if form.mode != arm64SVEEORImmediate {
						markReg(Reg(fmt.Sprintf("Z%d", form.second)))
					}
					if form.mode == arm64SVEEORPredicated {
						markReg(Reg(fmt.Sprintf("P%d", form.predicate)))
					}
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVETable(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.index)))
					markReg(Reg(fmt.Sprintf("Z%d", form.firstTable)))
					if form.tableCount == 2 {
						markReg(Reg(fmt.Sprintf("Z%d", (form.firstTable+1)%32)))
					}
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEUMULLB(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.first)))
					if form.mode == arm64SVEUMULLBVector {
						markReg(Reg(fmt.Sprintf("Z%d", form.second)))
					} else {
						markReg(Reg(fmt.Sprintf("Z%d", form.laneVector)))
					}
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEMultiplyAccumulateLong(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.first)))
					if form.mode == arm64SVEUMULLBVector {
						markReg(Reg(fmt.Sprintf("Z%d", form.second)))
					} else {
						markReg(Reg(fmt.Sprintf("Z%d", form.laneVector)))
					}
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
				if form, ok := decodeARM64RawSVEPermute(word); ok {
					markReg(Reg(fmt.Sprintf("Z%d", form.first)))
					markReg(Reg(fmt.Sprintf("Z%d", form.second)))
					markReg(Reg(fmt.Sprintf("Z%d", form.destination)))
				}
			}
		}
	}
	// Ensure arg regs exist.
	if len(c.sig.ArgRegs) > 0 {
		for i := 0; i < len(c.sig.Args) && i < len(c.sig.ArgRegs); i++ {
			markReg(c.sig.ArgRegs[i])
		}
	} else {
		cursor := arm64ABIRegisterCursor{}
		for _, typ := range c.sig.Args {
			if fields, aggregate := parseLiteralStructFields(typ); aggregate {
				for _, fieldType := range fields {
					reg, err := cursor.next(fieldType)
					if err != nil {
						break
					}
					markReg(reg)
				}
				continue
			}
			if reg, err := cursor.next(typ); err == nil {
				markReg(reg)
			}
		}
	}
	// Ensure register-return storage exists for all scalar result classes.
	if len(c.fpResults) == 0 && c.sig.Ret != Void {
		cursor := arm64ABIRegisterCursor{}
		if fields, aggregate := parseLiteralStructFields(c.sig.Ret); aggregate {
			for _, fieldType := range fields {
				if reg, err := cursor.next(fieldType); err == nil {
					markReg(reg)
				}
			}
		} else if reg, err := cursor.next(c.sig.Ret); err == nil {
			markReg(reg)
		}
	}
	// Keep lowering permissive for hand-written stubs that reference ad-hoc
	// registers via macros/aliases not captured in signatures.
	for i := 0; i <= 31; i++ {
		markReg(Reg(fmt.Sprintf("R%d", i)))
	}
	markReg(SP)
}

func (c *arm64Ctx) emitEntryAllocasAndArgInit() error {
	c.scanUsedRegs()
	regs := make([]string, 0, len(c.usedRegs))
	for r := range c.usedRegs {
		regs = append(regs, string(r))
	}
	sort.Strings(regs)

	// Keep allocas in LLVM's entry block and lower the source-level entry as a
	// separate block. LLVM forbids blockaddress constants that name the actual
	// entry block, while ARM64 ADR may legally address the first source block.
	c.b.WriteString("entry:\n")
	for _, rs := range regs {
		r := Reg(rs)
		name := c.slotName(r)
		c.regSlot[r] = name
		fmt.Fprintf(c.b, "  %s = alloca i64\n", name)
		fmt.Fprintf(c.b, "  store i64 0, ptr %s\n", name)
	}
	if spSlot := c.regSlot[SP]; spSlot != "" {
		minOff, maxOff, err := c.stackOffsetRange()
		if err != nil {
			return err
		}
		minimum, maximum, err := c.stackMovementRange()
		if err != nil {
			return err
		}
		minOff += minimum
		maxOff += maximum
		if minOff < -arm64MaxLocalStackSpan || maxOff > arm64MaxLocalStackSpan {
			return fmt.Errorf("ARM64 local stack footprint exceeds %d bytes", arm64MaxLocalStackSpan)
		}
		const guard = int64(64)
		bias := guard - minOff
		size := bias + maxOff + guard
		if size < 256 {
			size = 256
		}
		c.localStackSlot = "%local_stack"
		c.localStackSize = size
		fmt.Fprintf(c.b, "  %s = alloca [%d x i8], align 16\n", c.localStackSlot, size)
		base := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds [%d x i8], ptr %s, i32 0, i64 %d\n", base, size, c.localStackSlot, bias)
		addr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", addr, base)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", addr, spSlot)
	}

	// Vector registers: keep as <16 x i8> to cover most stdlib NEON byte ops.
	vIdx := make([]int, 0, len(c.usedVRegs))
	for i := range c.usedVRegs {
		vIdx = append(vIdx, i)
	}
	sort.Ints(vIdx)
	for _, i := range vIdx {
		if c.usedZRegs[i] {
			// Vn/Fn are the low 128/64 bits of Zn, not separate registers.
			// One scalable slot makes SVE writes visible to NEON/scalar reads.
			c.vRegSlot[i] = fmt.Sprintf("%%z%d", i)
			continue
		}
		name := c.vSlotName(i)
		c.vRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca <16 x i8>\n", name)
		fmt.Fprintf(c.b, "  store <16 x i8> zeroinitializer, ptr %s\n", name)
	}

	zIdx := make([]int, 0, len(c.usedZRegs))
	for i := range c.usedZRegs {
		zIdx = append(zIdx, i)
	}
	sort.Ints(zIdx)
	for _, i := range zIdx {
		name := fmt.Sprintf("%%z%d", i)
		c.zRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca <vscale x 16 x i8>\n", name)
		fmt.Fprintf(c.b, "  store <vscale x 16 x i8> zeroinitializer, ptr %s\n", name)
	}

	pIdx := make([]int, 0, len(c.usedPRegs))
	for i := range c.usedPRegs {
		pIdx = append(pIdx, i)
	}
	sort.Ints(pIdx)
	for _, i := range pIdx {
		name := fmt.Sprintf("%%p%d", i)
		c.pRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca <vscale x 16 x i1>\n", name)
		fmt.Fprintf(c.b, "  store <vscale x 16 x i1> zeroinitializer, ptr %s\n", name)
	}

	pnIdx := make([]int, 0, len(c.usedPNRegs))
	for i := range c.usedPNRegs {
		pnIdx = append(pnIdx, i)
	}
	sort.Ints(pnIdx)
	for _, i := range pnIdx {
		name := fmt.Sprintf("%%pn%d", i)
		c.pnRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca target(\"aarch64.svcount\")\n", name)
	}

	// Flags state: model "last CMP/SUBS/ANDS result" as two i64 slots.
	// This avoids SSA-phi complexity across CFG edges while we bootstrap.
	// We keep the actual NZCV bits, since stdlib asm relies on carry-based
	// conditions (BLS/BHS/HI/LO) after SUBS/ADDS.
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

	// Exclusive monitor state for LDAXR*/STLXR* lowering.
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
	fmt.Fprintf(c.b, "  %s = alloca i128\n", c.exclusiveValueSlot)
	fmt.Fprintf(c.b, "  store i128 0, ptr %s\n", c.exclusiveValueSlot)

	// Frame result slots: allocate addressable storage so patterns like
	// `$ret+off(FP)` and `MOVD x, ret+off(FP)` can work.
	// ABI0 parameter slots are writable as well: generated assembly commonly
	// spills an argument back to its own +off(FP) slot across nested calls.
	for i, p := range c.sig.Frame.Params {
		if p.Index < 0 || p.Index >= len(c.sig.Args) {
			return fmt.Errorf("arm64 entry %q: FP parameter slot +%d has invalid argument index %d", c.sig.Name, p.Offset, p.Index)
		}
		name := fmt.Sprintf("%%fp_param_%d", i)
		c.fpParamAlloca[p.Offset] = name
		fmt.Fprintf(c.b, "  %s = alloca %s\n", name, p.Type)
		value := fmt.Sprintf("%%arg%d", p.Index)
		if fields := frameSlotFields(p); len(fields) != 0 {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s%s\n", extracted, c.sig.Args[p.Index], value, frameSlotExtractSuffix(p))
			value = "%" + extracted
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", p.Type, value, name)
	}

	for _, r := range c.fpResults {
		name := fmt.Sprintf("%%fp_ret_%d", r.Index)
		c.fpResAllocaIdx[r.Index] = name
		c.fpResAllocaOff[r.Offset] = name
		fmt.Fprintf(c.b, "  %s = alloca %s\n", name, r.Type)
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", r.Type, llvmZeroValue(r.Type), name)
	}

	// Map args -> the independent integer and floating-point ABIInternal banks,
	// or to an explicit helper register assignment.
	if len(c.sig.ArgRegs) > 0 {
		if len(c.sig.ArgRegs) != len(c.sig.Args) {
			return fmt.Errorf("arm64 entry %q: %d explicit argument registers for %d arguments", c.sig.Name, len(c.sig.ArgRegs), len(c.sig.Args))
		}
		for i, reg := range c.sig.ArgRegs {
			if _, aggregate := parseLiteralStructFields(c.sig.Args[i]); aggregate {
				return fmt.Errorf("arm64 entry %q: explicit register for aggregate argument %d is ambiguous", c.sig.Name, i)
			}
			if err := c.storeABIRegisterValue(reg, c.sig.Args[i], fmt.Sprintf("%%arg%d", i)); err != nil {
				return err
			}
		}
		return nil
	}

	cursor := arm64ABIRegisterCursor{}
	for ai := 0; ai < len(c.sig.Args); ai++ {
		arg := fmt.Sprintf("%%arg%d", ai)
		argTy := c.sig.Args[ai]
		if fields, aggregate := parseLiteralStructFields(argTy); aggregate {
			for fi, fTy := range fields {
				r, err := cursor.next(fTy)
				if err != nil {
					return nil
				}
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", t, argTy, arg, fi)
				if err := c.storeABIRegisterValue(r, fTy, "%"+t); err != nil {
					return err
				}
			}
			continue
		}

		r, err := cursor.next(argTy)
		if err != nil {
			return nil
		}
		if err := c.storeABIRegisterValue(r, argTy, arg); err != nil {
			return err
		}
	}
	return nil
}

func (c *arm64Ctx) stackOffsetRange() (minOff, maxOff int64, err error) {
	add := func(off, size int64) {
		if off < -arm64MaxLocalStackSpan || off > arm64MaxLocalStackSpan ||
			size < 0 || size > arm64MaxLocalStackSpan {
			err = fmt.Errorf("ARM64 local stack operand exceeds %d bytes", arm64MaxLocalStackSpan)
			return
		}
		if off < minOff {
			minOff = off
		}
		if end := off + size; end > maxOff {
			maxOff = end
		}
	}
	for _, block := range c.blocks {
		for _, original := range block.instrs {
			ins := arm64StackInstruction(original)
			for _, arg := range ins.Args {
				if arg.Kind == OpMem && (arg.Mem.Base == SP || arg.Mem.Base == Reg("RSP") || arg.Mem.Base == ZR) {
					// Four 128-bit NEON registers are the largest ordinary
					// structured transfer. Scalar/pair forms fit this bound too.
					add(arg.Mem.Off, 64)
				}
			}
			op := strings.ToUpper(string(ins.Op))
			if (op != "BL" && op != "CALL") || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				continue
			}
			symbol := strings.TrimSpace(ins.Args[0].Sym)
			if !strings.HasSuffix(symbol, "(SB)") || strings.HasSuffix(symbol, "<ABIInternal>(SB)") {
				continue
			}
			sig, ok := c.sigs[c.resolve(strings.TrimSuffix(symbol, "(SB)"))]
			if !ok || len(sig.ArgRegs) != 0 {
				continue
			}
			for _, slot := range sig.Frame.Params {
				add(slot.Offset, frameTypeSize(slot.Type, 8))
			}
			for _, slot := range sig.Frame.Results {
				add(slot.Offset, frameTypeSize(slot.Type, 8))
			}
		}
	}
	return minOff, maxOff, err
}

func arm64ValueAsI64(c *arm64Ctx, ty LLVMType, v string) (out string, ok bool, err error) {
	switch ty {
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, v)
		return "%" + t, true, nil
	case I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", t, v)
		return "%" + t, true, nil
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i64\n", t, v)
		return "%" + t, true, nil
	case I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i64\n", t, v)
		return "%" + t, true, nil
	case I32:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v)
		return "%" + t, true, nil
	case I64:
		return v, true, nil
	case LLVMType("double"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, v)
		return "%" + t, true, nil
	case LLVMType("float"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", t, v)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		return "%" + z, true, nil
	default:
		return "", false, nil
	}
}

func parseLiteralStructFields(ty LLVMType) (fields []LLVMType, ok bool) {
	s := strings.TrimSpace(string(ty))
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}"))
	if inner == "" {
		return nil, false
	}
	parts := strings.Split(inner, ",")
	fields = make([]LLVMType, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, false
		}
		fields = append(fields, LLVMType(p))
	}
	return fields, true
}

func literalFieldsAllScalar(fields []LLVMType) bool {
	for _, ty := range fields {
		switch ty {
		case Ptr, I1, I8, I16, I32, I64:
			// ok
		default:
			return false
		}
	}
	return true
}

func llvmZeroValue(ty LLVMType) string {
	switch string(ty) {
	case "ptr":
		return "null"
	case "i1":
		return "false"
	case "i8", "i16", "i32", "i64":
		return "0"
	case "float":
		return "0.000000e+00"
	case "double":
		return "0.000000e+00"
	default:
		// Fallback for aggregates and other scalar types.
		return "zeroinitializer"
	}
}

func (c *arm64Ctx) loadReg(r Reg) (string, error) {
	if r == ZR {
		return "0", nil
	}
	if r == Reg("RSP") {
		r = SP
	}
	if _, ok := arm64ParseFReg(r); ok {
		v, err := c.loadVReg(r)
		if err != nil {
			return "", err
		}
		lanes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", lanes, v)
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i64 0\n", low, lanes)
		return "%" + low, nil
	}
	slot, ok := c.regSlot[r]
	if !ok {
		return "", fmt.Errorf("arm64: unknown reg %s", r)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *arm64Ctx) ptrFromSB(sym string) (ptr string, err error) {
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
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", t, p, off)
	return "%" + t, nil
}

func (c *arm64Ctx) storeReg(r Reg, v string) error {
	if r == ZR {
		return nil
	}
	if r == Reg("RSP") {
		r = SP
	}
	if _, ok := arm64ParseFReg(r); ok {
		lanes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %s, i64 0\n", lanes, v)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, lanes)
		return c.storeVReg(r, "%"+bytes)
	}
	slot, ok := c.regSlot[r]
	if !ok {
		return fmt.Errorf("arm64: unknown reg %s", r)
	}
	fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
	return nil
}

func (c *arm64Ctx) loadVReg(r Reg) (string, error) {
	idx, ok := arm64ParseVReg(r)
	if !ok {
		idx, ok = arm64ParseFReg(r)
	}
	if !ok {
		return "", fmt.Errorf("arm64: not a vector register %s", r)
	}
	slot, ok := c.vRegSlot[idx]
	if !ok {
		return "", fmt.Errorf("arm64: unknown vreg %s", r)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *arm64Ctx) storeVReg(r Reg, v string) error {
	idx, ok := arm64ParseVReg(r)
	if !ok {
		idx, ok = arm64ParseFReg(r)
	}
	if !ok {
		return fmt.Errorf("arm64: not a vector register %s", r)
	}
	slot, ok := c.vRegSlot[idx]
	if !ok {
		return fmt.Errorf("arm64: unknown vreg %s", r)
	}
	if zSlot := c.zRegSlot[idx]; zSlot != "" {
		// Architectural NEON/scalar writes clear the scalable upper bits.
		fmt.Fprintf(c.b, "  store <vscale x 16 x i8> zeroinitializer, ptr %s\n", zSlot)
	}
	fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s\n", v, slot)
	return nil
}
