package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"sort"
	"strconv"
	"strings"
)

type arm64Ctx struct {
	b        *strings.Builder
	sig      asm.FuncSig
	resolve  func(string) string
	sigs     map[string]asm.FuncSig
	annotate bool

	tmp int

	blocks []arm64Block

	usedRegs map[asm.Reg]bool
	regSlot  map[asm.Reg]string // reg -> alloca name

	localStackSlot string // byte-addressable backing storage for ARM64 SP/RSP frame accesses
	frameSize      int64

	usedVRegs map[int]bool
	vRegSlot  map[int]string // vreg index -> alloca name (<16 x i8>)

	flagsNSlot   string
	flagsZSlot   string
	flagsCSlot   string
	flagsVSlot   string
	flagsWritten bool

	exclusiveValidSlot string
	exclusivePtrSlot   string
	exclusiveSizeSlot  string
	exclusiveValueSlot string

	fpParams       map[int64]asm.FrameSlot // off(FP) -> slot
	fpResults      []asm.FrameSlot         // result slots (Index is result index)
	fpResAllocaOff map[int64]string        // off(FP) -> alloca
	fpResAllocaIdx map[int]string          // result index -> alloca
	fpResWritten   map[int]bool            // result index -> direct writes to fp slot
	fpResAddrTaken map[int]bool            // result index -> fp result slot address escaped
}

func newARM64Ctx(b *strings.Builder, fn asm.Func, sig asm.FuncSig, resolve func(string) string, sigs map[string]asm.FuncSig, annotate bool) *arm64Ctx {
	c := &arm64Ctx{
		b:              b,
		sig:            sig,
		resolve:        resolve,
		sigs:           sigs,
		annotate:       annotate,
		blocks:         arm64SplitBlocks(fn),
		frameSize:      fn.FrameSize,
		usedRegs:       map[asm.Reg]bool{},
		regSlot:        map[asm.Reg]string{},
		usedVRegs:      map[int]bool{},
		vRegSlot:       map[int]string{},
		fpParams:       map[int64]asm.FrameSlot{},
		fpResAllocaOff: map[int64]string{},
		fpResAllocaIdx: map[int]string{},
		fpResWritten:   map[int]bool{},
		fpResAddrTaken: map[int]bool{},
	}
	for _, s := range sig.Frame.Params {
		c.fpParams[s.Offset] = s
	}
	c.fpResults = append([]asm.FrameSlot(nil), sig.Frame.Results...)
	return c
}

func (c *arm64Ctx) emitSourceComment(ins asm.Instr) {
	if !c.annotate {
		return
	}
	asm.EmitIRSourceComment(c.b, ins.Raw)
}

func (c *arm64Ctx) newTmp() string {
	c.tmp++
	return fmt.Sprintf("t%d", c.tmp)
}

func (c *arm64Ctx) slotName(r asm.Reg) string {
	// Make the name LLVM-label friendly to keep the IR readable.
	return "%" + asm.LLVMBlockName("reg_"+string(r))
}

func (c *arm64Ctx) vSlotName(idx int) string {
	return fmt.Sprintf("%%v%d", idx)
}

func arm64ParseVReg(r asm.Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "V") {
		return 0, false
	}
	// Strip optional lane suffix: V8.D[0], V5.B16, etc.
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		s = s[:dot]
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "V"))
	if err != nil || n < 0 || n > 31 {
		return 0, false
	}
	return n, true
}

func arm64ParseFReg(r asm.Reg) (idx int, ok bool) {
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

func (c *arm64Ctx) scanUsedRegs() {
	markReg := func(r asm.Reg) {
		if r == "" {
			return
		}
		if r == "RSP" {
			r = asm.SP
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
	markOp := func(op asm.Operand) {
		switch op.Kind {
		case asm.OpReg:
			markReg(op.Reg)
		case asm.OpMem:
			markReg(op.Mem.Base)
			if op.Mem.Index != "" {
				markReg(op.Mem.Index)
			}
		case asm.OpRegList:
			for _, r := range op.RegList {
				markReg(r)
			}
		}
	}

	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			for _, op := range ins.Args {
				markOp(op)
			}
			if ins.Op == asm.OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm && ins.Args[0].ImmRaw == "" {
				if decoded, ok := DecodeRawWord(uint32(ins.Args[0].Imm)); ok {
					for _, op := range decoded.Args {
						markOp(op)
					}
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
		// Go internal ABI on arm64 uses up to 16 integer argument registers.
		// For aggregate args like {ptr,len,cap} we need registers for each word,
		// since ABIInternal asm expects those words in consecutive registers.
		n := 0
		for _, ty := range c.sig.Args {
			if fields, ok := asm.ParseLiteralStructFields(ty); ok && asm.LiteralFieldsAllScalar(fields) {
				n += len(fields)
			} else {
				n++
			}
		}
		for i := 0; i < n && i < 16; i++ {
			markReg(asm.Reg(fmt.Sprintf("R%d", i)))
		}
	}
	// Ensure return reg exists.
	markReg(asm.Reg("R0"))
	// Keep lowering permissive for hand-written stubs that reference ad-hoc
	// registers via macros/aliases not captured in signatures.
	for i := 0; i <= 31; i++ {
		markReg(asm.Reg(fmt.Sprintf("R%d", i)))
	}
	markReg(asm.SP)
}

func (c *arm64Ctx) hasSPMem() bool {
	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			for _, arg := range ins.Args {
				if arg.Kind == asm.OpMem && (arg.Mem.Base == asm.SP || arg.Mem.Base == "RSP") {
					return true
				}
			}
		}
	}
	return false
}

func (c *arm64Ctx) hasOutgoingSPArgs() bool {
	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			for _, arg := range ins.Args {
				if arg.Kind == asm.OpMem && (arg.Mem.Base == asm.SP || arg.Mem.Base == "RSP") && arg.Mem.Off >= 8 {
					return true
				}
			}
		}
	}
	return false
}

func (c *arm64Ctx) stackOffsetRange() (minOff, maxOff int64) {
	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			for _, arg := range ins.Args {
				if arg.Kind != asm.OpMem || (arg.Mem.Base != asm.SP && arg.Mem.Base != "RSP") {
					continue
				}
				if arg.Mem.Off < minOff {
					minOff = arg.Mem.Off
				}
				if end := arg.Mem.Off + 16; end > maxOff {
					maxOff = end
				}
			}
		}
	}
	return minOff, maxOff
}

func (c *arm64Ctx) emitEntryAllocasAndArgInit() error {
	c.scanUsedRegs()
	regs := make([]string, 0, len(c.usedRegs))
	for r := range c.usedRegs {
		regs = append(regs, string(r))
	}
	sort.Strings(regs)

	c.b.WriteString(asm.LLVMBlockName("entry") + ":\n")
	for _, rs := range regs {
		r := asm.Reg(rs)
		name := c.slotName(r)
		c.regSlot[r] = name
		fmt.Fprintf(c.b, "  %s = alloca i64\n", name)
		fmt.Fprintf(c.b, "  store i64 0, ptr %s\n", name)
	}
	if spSlot, ok := c.regSlot[asm.SP]; ok && c.hasSPMem() {
		minOff, maxOff := c.stackOffsetRange()
		const guard = int64(64)
		bias := guard - minOff
		size := bias + maxOff + guard
		if size < 256 {
			size = 256
		}
		c.localStackSlot = "%local_stack"
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
		name := c.vSlotName(i)
		c.vRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca <16 x i8>\n", name)
		fmt.Fprintf(c.b, "  store <16 x i8> zeroinitializer, ptr %s\n", name)
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
	fmt.Fprintf(c.b, "  %s = alloca i64\n", c.exclusiveValueSlot)
	fmt.Fprintf(c.b, "  store i64 0, ptr %s\n", c.exclusiveValueSlot)

	// Frame result slots: allocate addressable storage so patterns like
	// `$ret+off(FP)` and `MOVD x, ret+off(FP)` can work.
	for _, r := range c.fpResults {
		name := fmt.Sprintf("%%fp_ret_%d", r.Index)
		c.fpResAllocaIdx[r.Index] = name
		c.fpResAllocaOff[r.Offset] = name
		fmt.Fprintf(c.b, "  %s = alloca %s\n", name, r.Type)
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", r.Type, asm.LLVMZeroValue(r.Type), name)
	}

	// Map args -> regs (best-effort for ABIInternal-style asm, and for helper<> reg assignments).
	if len(c.sig.ArgRegs) > 0 {
		// Custom arg->reg assignment (used by helper<> bodies).
		for i := 0; i < len(c.sig.Args) && i < len(c.sig.ArgRegs); i++ {
			r := c.sig.ArgRegs[i]
			arg := fmt.Sprintf("%%arg%d", i)
			argTy := c.sig.Args[i]
			v, ok, err := arm64ValueAsI64(c, argTy, arg)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if err := c.storeReg(r, v); err != nil {
				return err
			}
		}
		return nil
	}

	// Default: flatten aggregate args into consecutive argument registers
	// following the Go internal ABI word ordering.
	regIdx := 0
	for ai := 0; ai < len(c.sig.Args) && regIdx < 16; ai++ {
		arg := fmt.Sprintf("%%arg%d", ai)
		argTy := c.sig.Args[ai]
		if fields, ok := asm.ParseLiteralStructFields(argTy); ok && asm.LiteralFieldsAllScalar(fields) {
			for fi, fTy := range fields {
				if regIdx >= 16 {
					break
				}
				r := asm.Reg(fmt.Sprintf("R%d", regIdx))
				regIdx++
				slot, ok := c.regSlot[r]
				if !ok {
					continue
				}
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", t, argTy, arg, fi)
				v, ok, err := arm64ValueAsI64(c, fTy, "%"+t)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
			}
			continue
		}

		r := asm.Reg(fmt.Sprintf("R%d", regIdx))
		regIdx++
		slot, ok := c.regSlot[r]
		if !ok {
			continue
		}
		v, ok, err := arm64ValueAsI64(c, argTy, arg)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
	}
	return nil
}

func arm64ValueAsI64(c *arm64Ctx, ty asm.LLVMType, v string) (out string, ok bool, err error) {
	switch ty {
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, v)
		return "%" + t, true, nil
	case asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", t, v)
		return "%" + t, true, nil
	case asm.I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i64\n", t, v)
		return "%" + t, true, nil
	case asm.I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i64\n", t, v)
		return "%" + t, true, nil
	case asm.I32:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v)
		return "%" + t, true, nil
	case asm.I64:
		return v, true, nil
	case asm.LLVMType("double"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, v)
		return "%" + t, true, nil
	case asm.LLVMType("float"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", t, v)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, t)
		return "%" + z, true, nil
	default:
		return "", false, nil
	}
}

// ok

// Fallback for aggregates and other scalar types.

func (c *arm64Ctx) loadReg(r asm.Reg) (string, error) {
	if r == asm.ZR {
		return "0", nil
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
	if r == "RSP" {
		r = asm.SP
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
	base, off, ok := asm.ParseSBRef(sym)
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
	p := asm.LLVMGlobal(res)
	if off == 0 {
		return p, nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", t, p, off)
	return "%" + t, nil
}

func (c *arm64Ctx) storeReg(r asm.Reg, v string) error {
	if r == asm.ZR {
		return nil
	}
	if _, ok := arm64ParseFReg(r); ok {
		lanes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %s, i64 0\n", lanes, v)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, lanes)
		return c.storeVReg(r, "%"+bytes)
	}
	if r == "RSP" {
		r = asm.SP
	}
	slot, ok := c.regSlot[r]
	if !ok {
		return fmt.Errorf("arm64: unknown reg %s", r)
	}
	fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
	return nil
}

func (c *arm64Ctx) loadVReg(r asm.Reg) (string, error) {
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

func (c *arm64Ctx) storeVReg(r asm.Reg, v string) error {
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
	fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s\n", v, slot)
	return nil
}
