package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"sort"
	"strings"
)

type armCtx struct {
	b        *strings.Builder
	sig      asm.FuncSig
	resolve  func(string) string
	sigs     map[string]asm.FuncSig
	annotate bool

	tmp int

	blocks []armBlock

	usedRegs  map[asm.Reg]bool
	regSlot   map[asm.Reg]string
	usedFRegs map[asm.Reg]bool
	fRegSlot  map[asm.Reg]string

	flagsNSlot   string
	flagsZSlot   string
	flagsCSlot   string
	flagsVSlot   string
	flagsWritten bool

	curPreInc bool
	curSubOff bool

	exclusiveValidSlot string
	exclusivePtrSlot   string
	exclusiveSizeSlot  string
	exclusiveValueSlot string

	fpParams       map[int64]asm.FrameSlot
	fpParamAlloca  map[int64]string
	fpResults      []asm.FrameSlot
	fpResAllocaOff map[int64]string
	fpResAllocaIdx map[int]string
	fpResWritten   map[int]bool
	fpResAddrTaken map[int]bool
}

func newARMCtx(b *strings.Builder, fn asm.Func, sig asm.FuncSig, resolve func(string) string, sigs map[string]asm.FuncSig, annotate bool) *armCtx {
	c := &armCtx{
		b:              b,
		sig:            sig,
		resolve:        resolve,
		sigs:           sigs,
		annotate:       annotate,
		blocks:         armSplitBlocks(fn),
		usedRegs:       map[asm.Reg]bool{},
		regSlot:        map[asm.Reg]string{},
		usedFRegs:      map[asm.Reg]bool{},
		fRegSlot:       map[asm.Reg]string{},
		fpParams:       map[int64]asm.FrameSlot{},
		fpParamAlloca:  map[int64]string{},
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

func (c *armCtx) emitSourceComment(ins asm.Instr) {
	if !c.annotate {
		return
	}
	asm.EmitIRSourceComment(c.b, ins.Raw)
}

func (c *armCtx) newTmp() string {
	c.tmp++
	return fmt.Sprintf("t%d", c.tmp)
}

func (c *armCtx) slotName(r asm.Reg) string {
	return "%" + armLLVMBlockName("reg_"+string(r))
}

func (c *armCtx) scanUsedRegs() {
	isFReg := func(r asm.Reg) bool {
		return strings.HasPrefix(string(r), "F")
	}
	markReg := func(r asm.Reg) {
		if r == "" {
			return
		}
		if isFReg(r) {
			c.usedFRegs[r] = true
		} else {
			c.usedRegs[r] = true
		}
	}
	markOp := func(op asm.Operand) {
		switch op.Kind {
		case asm.OpReg, asm.OpRegShift:
			markReg(op.Reg)
			markReg(op.ShiftReg)
		case asm.OpMem:
			markReg(op.Mem.Base)
			markReg(op.Mem.Index)
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
		}
	}
	if len(c.sig.ArgRegs) > 0 {
		for i := 0; i < len(c.sig.Args) && i < len(c.sig.ArgRegs); i++ {
			markReg(c.sig.ArgRegs[i])
		}
	} else {
		for i := 0; i < len(c.sig.Args) && i < 4; i++ {
			markReg(asm.Reg(fmt.Sprintf("R%d", i)))
		}
	}
	for i := 0; i <= 15; i++ {
		markReg(asm.Reg(fmt.Sprintf("R%d", i)))
	}
	markReg(asm.SP)
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
		r := asm.Reg(rs)
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
		r := asm.Reg(rs)
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
		if p.Field >= 0 {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", extracted, c.sig.Args[p.Index], value, p.Field)
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
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", r.Type, asm.LLVMZeroValue(r.Type), name)
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

func armValueAsI32(c *armCtx, ty asm.LLVMType, v string) (out string, ok bool, err error) {
	switch ty {
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i32\n", t, v)
		return "%" + t, true, nil
	case asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i32\n", t, v)
		return "%" + t, true, nil
	case asm.I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i32\n", t, v)
		return "%" + t, true, nil
	case asm.I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", t, v)
		return "%" + t, true, nil
	case asm.I32:
		return v, true, nil
	case asm.I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v)
		return "%" + t, true, nil
	default:
		return "", false, nil
	}
}

func (c *armCtx) loadReg(r asm.Reg) (string, error) {
	slot, ok := c.regSlot[r]
	if !ok {
		return "", fmt.Errorf("arm: unknown reg %s", r)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *armCtx) storeReg(r asm.Reg, v string) error {
	slot, ok := c.regSlot[r]
	if !ok {
		return fmt.Errorf("arm: unknown reg %s", r)
	}
	fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n", v, slot)
	return nil
}

func (c *armCtx) loadFReg(r asm.Reg) (string, error) {
	slot, ok := c.fRegSlot[r]
	if !ok {
		return "", fmt.Errorf("arm: unknown freg %s", r)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *armCtx) storeFReg(r asm.Reg, v string) error {
	slot, ok := c.fRegSlot[r]
	if !ok {
		return fmt.Errorf("arm: unknown freg %s", r)
	}
	fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
	return nil
}

func (c *armCtx) ptrFromSB(sym string) (string, error) {
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
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i32 %d\n", t, p, off)
	return "%" + t, nil
}
