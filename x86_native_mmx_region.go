package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

type x86NativeMMXSite struct {
	instruction Instr
	word        *x86MMXWordForm
	integer     *x86LegacyMMXReadForm
	maskStore   *amd64ImplicitMaskMoveSpec
	moveMask    *x86MoveMaskForm
}

// This private source-bound region keeps the real MMX/x87 instructions
// together through EMMS. Numerical availability remains a separate must-domain;
// neither a source spelling nor the emitter's private image supplies inputs.
type x86NativeMMXRegion struct {
	begin, end        int
	sites             map[int]x86NativeMMXSite
	function          [32]byte
	signature         [32]byte
	instructions      []Instr
	arch, triple      string
	fpExtent          int64
	fpRead, fpWritten []bool
	gpRead, gpWritten [16]bool
	xRead, xWritten   [16]bool
}

func x86NativeMMXInstruction(ins Instr, arch string) (x86NativeMMXSite, bool, error) {
	site := x86NativeMMXSite{instruction: ins}
	if ins.Op == "EMMS" {
		if len(ins.Args) != 0 {
			return site, true, fmt.Errorf("%s EMMS expects no operands", arch)
		}
		return site, true, nil
	}
	if form, known, err := x86MMXWordProperties(ins, arch); known {
		native := form
		site.word = &native
		return site, true, err
	}
	if form, known, err := x86LegacyMMXReadProperties(ins, arch); known && form.mmx {
		native := form
		site.integer = &native
		return site, true, err
	}
	if spec, known, err := x86ImplicitMaskMoveProperties(ins.Op, ins, arch); known && spec.byteWidth == 8 {
		native := spec
		site.maskStore = &native
		return site, true, err
	}
	if form, known, err := x86MoveMaskProperties(ins.Op, ins, arch); known && form.byteWidth == 8 {
		// Only the matching MMX site needs an escaping form allocation.
		native := form
		site.moveMask = &native
		return site, true, err
	}
	return site, false, nil
}

func newX86NativeMMXRegion(fn Func, sig FuncSig, arch, triple string) (*x86NativeMMXRegion, error) {
	plan := &x86NativeMMXRegion{begin: -1, end: -1, sites: make(map[int]x86NativeMMXSite), arch: arch, triple: triple}
	fail := func(reason string) (*x86NativeMMXRegion, error) {
		return nil, fmt.Errorf("%w: native MMX region: %s", ErrProbeNeedsContext, reason)
	}
	for ordinal, ins := range fn.Instrs {
		site, known, err := x86NativeMMXInstruction(ins, arch)
		if err != nil {
			return nil, err
		}
		if known {
			if plan.begin < 0 {
				plan.begin = ordinal
			}
			plan.end = ordinal
			plan.sites[ordinal] = site
		}
	}
	if plan.begin < 0 {
		return nil, nil
	}
	if !x86ScalarFloatIntegerNativeTarget(arch, triple) || fn.FrameSize != 0 || fn.ArgSize < 0 || fn.ArgSize > 4096 ||
		len(fn.Instrs) > 512 || strings.Contains(fn.Sym, "<") || len(fn.X86RawText) != 0 || fn.X86RawAlign != 0 ||
		len(sig.ArgRegs) != 0 || sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil ||
		sig.WASMContext != "" || sig.WASMNative || sig.x86CallerRegions != nil || sig.x86FixedLocal != nil ||
		sig.amd64GoArguments != nil || sig.x86BorrowedBoolTail || fn.x86SourceStack != nil || fn.x86FixedLocal != nil ||
		fn.x86ContinuationFlow != nil || fn.x86DirectTailRoot != nil || fn.x86RawReplay != nil || fn.x86BoolCalls != nil ||
		len(fn.x86ContinuationAddresses) != 0 || len(fn.x86IndirectLabels) != 0 || x86X87ValueFlowNeeded(fn) {
		return fail("needs its complete ordinary bounded native leaf, not another entry/storage owner")
	}
	for ordinal, ins := range fn.Instrs {
		if !x86ResultNamedPredicateInstruction(ins) || ins.Op == OpCALL || ins.Op == OpJMP ||
			ins.Op == OpLABEL || isAMD64ConditionalBranch(ins.Op) || ins.x86NumericalRead != nil ||
			len(ins.x86SourceStackFP) != 0 || len(ins.x86CallerMemory) != 0 || len(ins.x86FixedLocalMemory) != 0 {
			return fail("a foreign effect or source CFG cannot acquire physical MMX state")
		}
		if ordinal >= plan.begin && ordinal <= plan.end {
			if _, present := plan.sites[ordinal]; !present {
				return fail("MMX effects must form one uninterrupted region")
			}
		}
	}
	if fn.Instrs[plan.end].Op != "EMMS" {
		return fail("every MMX region must close its real x87 tag state with EMMS")
	}
	for _, slots := range [][]FrameSlot{sig.Frame.Params, sig.Frame.Results} {
		for _, slot := range slots {
			width := x86FrameScalarBytes(slot.Type, arch)
			if width == 0 || slot.Offset < 0 || slot.Offset > fn.ArgSize-width {
				return fail("typed FP layout is not bounded by its actual source TEXT")
			}
			if end := slot.Offset + width; end > plan.fpExtent {
				plan.fpExtent = end
			}
		}
	}
	plan.fpRead, plan.fpWritten = make([]bool, plan.fpExtent), make([]bool, plan.fpExtent)
	for _, site := range plan.sites {
		if site.word != nil {
			form := site.word
			if form.nonTemporal && form.destination.Kind == OpFP {
				return fail("non-temporal FP stores need original native backing, not a private image")
			}
			if err := plan.operand(form.source, form.bytes, false); err != nil {
				return fail(err.Error())
			}
			width := form.bytes
			if form.targetX {
				width = 16
			}
			if err := plan.operand(form.destination, width, true); err != nil {
				return fail(err.Error())
			}
		} else if site.integer != nil {
			form := site.integer
			if err := plan.operand(form.source, int64(form.memoryBytes), false); err != nil {
				return fail(err.Error())
			}
		} else if site.moveMask != nil {
			if err := plan.operand(site.instruction.Args[0], 8, false); err != nil {
				return fail(err.Error())
			}
			if err := plan.operand(site.instruction.Args[1], 4, true); err != nil {
				return fail(err.Error())
			}
		} else if site.maskStore != nil {
			for _, operand := range site.instruction.Args {
				if err := plan.operand(operand, 8, false); err != nil {
					return fail(err.Error())
				}
			}
			if err := plan.operand(Operand{Kind: OpMem, Mem: MemRef{Base: DI}}, 8, true); err != nil {
				return fail(err.Error())
			}
		}
	}
	var err error
	plan.function, err = x86CallerSourceFingerprint(fn)
	if err != nil {
		return nil, err
	}
	plan.signature, err = x86CallerSourceFingerprint(sig)
	if err != nil {
		return nil, err
	}
	plan.instructions = cloneX86ReplayInstrs(fn.Instrs)
	return plan, nil
}

func (plan *x86NativeMMXRegion) operand(operand Operand, width int64, write bool) error {
	switch operand.Kind {
	case OpImm:
		return nil // Only the independently validated immediate-count row enters here.
	case OpReg:
		if _, mmx := amd64ParseMReg(operand.Reg); mmx {
			return nil
		}
		if index, vector := amd64ParseXReg(operand.Reg); vector && index < 16 {
			plan.xRead[index], plan.xWritten[index] = plan.xRead[index] || !write, plan.xWritten[index] || write
			return nil
		}
		index, _, valid := x86ResultGP(operand.Reg, x86ResultPointerWord(plan.arch), plan.arch)
		if !valid {
			return fmt.Errorf("physical frame registers need their independent source contract")
		}
		plan.gpRead[index], plan.gpWritten[index] = plan.gpRead[index] || !write, plan.gpWritten[index] || write
		return nil
	case OpFP:
		if width <= 0 || operand.FPOffset < 0 || operand.FPOffset > plan.fpExtent-width {
			return fmt.Errorf("FP operand exceeds its complete typed byte image")
		}
		for offset := operand.FPOffset; offset < operand.FPOffset+width; offset++ {
			plan.fpRead[offset], plan.fpWritten[offset] = plan.fpRead[offset] || !write, plan.fpWritten[offset] || write
		}
		return nil
	case OpMem:
		if operand.Mem.Sym != "" || !x86OrdinaryNativeMemoryOperand(operand, plan.arch) {
			return fmt.Errorf("native memory needs an ordinary complete incoming-pointer address")
		}
		for _, reg := range []Reg{operand.Mem.Base, operand.Mem.Index} {
			if reg != "" {
				if err := plan.operand(Operand{Kind: OpReg, Reg: reg}, x86ResultPointerWord(plan.arch), false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return fmt.Errorf("symbolic/native storage needs its independent source binding")
}

func (plan *x86NativeMMXRegion) matches(fn Func, sig FuncSig, arch, triple string) bool {
	if plan == nil || plan.arch != arch || plan.triple != triple || !reflect.DeepEqual(plan.instructions, fn.Instrs) {
		return false
	}
	function, err := x86CallerSourceFingerprint(fn)
	if err != nil || function != plan.function {
		return false
	}
	signature, err := x86CallerSourceFingerprint(sig)
	return err == nil && signature == plan.signature
}

func (plan *x86NativeMMXRegion) matchesInstruction(ordinal int, ins Instr) bool {
	return plan != nil && ordinal >= 0 && ordinal < len(plan.instructions) && reflect.DeepEqual(plan.instructions[ordinal], ins)
}

func (plan *x86NativeMMXRegion) transfer(ordinal int, ins Instr, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) (bool, bool) {
	if plan == nil || ordinal < plan.begin || ordinal > plan.end {
		return false, false
	}
	site, present := plan.sites[ordinal]
	if !present || state == nil || arch != plan.arch || !plan.matchesInstruction(ordinal, ins) ||
		!x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	if state.shapeOnly || ins.Op == "EMMS" {
		return true, true // Grammar only, or the actual paired hardware tag operation.
	}
	read := func(operand Operand, width int64) bool {
		if operand.Kind == OpReg {
			mask := uint8((uint16(1) << uint(width)) - 1)
			if index, valid := amd64ParseMReg(operand.Reg); valid {
				return state.nativeMMX[index]&mask == mask
			}
			if index, valid := amd64ParseXReg(operand.Reg); valid {
				return state.xmm[index]&uint16(mask) == uint16(mask)
			}
			if index, _, valid := x86ResultGP(operand.Reg, width, arch); valid &&
				(state.pointerGP[index] || state.callerAddressGP[index]) {
				return false // Opaque address bits cannot become numeric MMX bytes.
			}
		}
		return x86ResultReadWithNativeContinuation(ins, operand, width, state, owned, arch, true)
	}
	if form := site.word; form != nil {
		if !read(form.source, form.bytes) {
			return false, true
		}
		if form.targetM {
			index, _ := amd64ParseMReg(form.destination.Reg)
			state.nativeMMX[index] = 0xff // MOVL clears the remaining high32.
			return true, true
		}
		if form.targetX {
			index, _ := amd64ParseXReg(form.destination.Reg)
			state.writeVector(index, 16, 0xffff, true)
			return true, true
		}
		if form.destination.Kind == OpMem {
			return x86ResultIncomingPointerAddressIdentity(form.destination, state, arch), true
		}
		if form.destination.Kind == OpReg {
			index, _, valid := x86ResultGP(form.destination.Reg, form.bytes, arch)
			if !valid {
				return false, true
			}
			state.canonicalGP[index] = 0
			if form.bytes == 4 {
				state.canonicalGP[index] = 0xf0
			}
			state.callerAddressGP[index], state.callerAddressOrigin[index] = false, 0
			state.resultAddressGP[index] = x86ResultSlotAddress{}
		}
		return x86ResultStore(form.destination, form.bytes, state, owned, resultOffset, arch), true
	}
	if site.moveMask != nil {
		if !read(ins.Args[0], 8) {
			return false, true
		}
		index, _, valid := x86ResultGP(ins.Args[1].Reg, 4, arch)
		if !valid {
			return false, true
		}
		// A physical mask produces a write-only r32. Its upper dword is
		// zero, never the old pointer, caller address or canonical bool.
		state.canonicalGP[index] = 0xf0
		state.callerAddressGP[index], state.callerAddressOrigin[index] = false, 0
		state.resultAddressGP[index] = x86ResultSlotAddress{}
		if state.boolFrameGP != nil {
			state.boolFrameGP[index] = x86ResultSlotAddress{}
		}
		return x86ResultStore(ins.Args[1], 4, state, owned, resultOffset, arch), true
	}
	if site.maskStore != nil {
		for _, operand := range ins.Args {
			if !read(operand, 8) {
				return false, true
			}
		}
		return x86ResultIncomingPointerAddressIdentity(Operand{Kind: OpMem, Mem: MemRef{Base: DI}}, state, arch), true
	}
	form := site.integer
	destination, _ := amd64ParseMReg(ins.Args[form.destination].Reg)
	self := form.source.Kind == OpReg && form.source.Reg == ins.Args[form.destination].Reg
	zero := self && (form.canonical == "PXOR" || form.canonical == "PANDN" ||
		strings.HasPrefix(string(form.canonical), "PCMPEQ") || strings.HasPrefix(string(form.canonical), "PCMPGT"))
	if !zero {
		width := int64(8)
		if form.memoryBytes != 0 {
			width = int64(form.memoryBytes)
		}
		if !read(form.source, width) || form.spec.table != x86LegacyMMXShuffle && state.nativeMMX[destination] != 0xff {
			return false, true
		}
	}
	state.nativeMMX[destination] = 0xff
	return true, true
}
