package plan9asm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// amd64Ctx is the shared x86 lowering context for GOARCH=amd64 and GOARCH=386.
type amd64Ctx struct {
	b   *strings.Builder
	sig FuncSig
	// goarch distinguishes the 32-bit x86 rules from amd64 while sharing the
	// common x86 lowering implementation.
	goarch       string
	targetTriple string

	resolve        func(string) string
	sigs           map[string]FuncSig
	annotate       bool
	continuations  map[string]x86Continuation
	indirectLabels []string

	tmp int

	blocks []amd64Block
	// Mapping between linear instruction index and block index. Used to
	// resolve n(PC) branches which are instruction-relative.
	blockBase  []int
	blockByIdx map[int]int

	usedRegs map[Reg]bool
	regSlot  map[Reg]string // gp reg -> alloca name

	usedXRegs map[int]bool
	xRegSlot  map[int]string // xmm reg index -> alloca name (<16 x i8>)

	usedYRegs map[int]bool
	yRegSlot  map[int]string // ymm reg index -> alloca name (<32 x i8>)

	usedZRegs map[int]bool
	zRegSlot  map[int]string // zmm reg index -> alloca name (<64 x i8>)

	usedKRegs         map[int]bool
	kRegSlot          map[int]string // avx512 mask reg index -> alloca name (i64)
	usedX87           bool
	usesX87Convert    bool
	x87Slot           [8]string // x87 stack registers, represented as f64 values
	x87ControlSlot    string
	x87StatusSlot     string // condition-code status populated by FTST for FSTSW
	x87IntegerSlot    string // hardware FISTP result for explicit 386 x87 lowering
	mmxConversionSlot string // shared scratch for legacy SSE-to-MMX conversions
	x87Mode           X87Mode

	flagsZSlot     string
	flagsSltSlot   string // signed negative-style bit for J{L,LE,G,GE}-like checks
	flagsCFSlot    string // carry/borrow style bit for J{B,BE,A,AE,NC,C}-like checks
	flagsPFSlot    string // parity bit for J{P,PE,PS,NP,PO,PC}-like checks
	flagsOFSlot    string // overflow-style bit used by ADOX carry chain modeling
	flagsIDSlot    string // CPUID availability bit preserved by PUSHFL/POPFL
	flagsWritten   bool
	allowSPWrite   bool   // current instruction has an explicitly modeled 386 SP destination
	directionSlot  string // x86 DF, used by MOVS/STOS/SCAS instructions
	repeatPrefix   string // pending REP/REPN prefix for the following instruction
	vstackSlot     string // [64 x i64] virtual stack for PUSHQ/POPQ
	vspSlot        string // i64 virtual stack pointer (next free slot)
	localStackSlot string // byte-addressable backing storage for x86 SP references
	classicFrame   string // contiguous classic Go ABI frame used by 386 FP addressing
	classicSize    int64
	classicBias    int64

	fpParams       map[int64]FrameSlot // off(FP) -> slot
	fpParamAlloca  map[int64]string    // off(FP) -> mutable parameter shadow
	fpResults      []FrameSlot
	fpResAllocaOff map[int64]string // off(FP) -> alloca
	fpResAllocaIdx map[int]string   // result index -> alloca
	fpResWritten   map[int]bool     // result index -> whether written via +off(FP)
	fpResAddrTaken map[int]bool     // result index -> address of fp_ret_* escaped
}

func newAMD64Ctx(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotate bool) *amd64Ctx {
	return newX86Ctx(b, fn, sig, resolve, sigs, "amd64", "", annotate)
}

func newX86Ctx(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, goarch, targetTriple string, annotate bool) *amd64Ctx {
	c := &amd64Ctx{
		b:              b,
		sig:            sig,
		goarch:         goarch,
		targetTriple:   targetTriple,
		resolve:        resolve,
		sigs:           sigs,
		annotate:       annotate,
		blocks:         amd64SplitBlocks(fn),
		usedRegs:       map[Reg]bool{},
		regSlot:        map[Reg]string{},
		usedXRegs:      map[int]bool{},
		xRegSlot:       map[int]string{},
		usedYRegs:      map[int]bool{},
		yRegSlot:       map[int]string{},
		usedZRegs:      map[int]bool{},
		zRegSlot:       map[int]string{},
		usedKRegs:      map[int]bool{},
		kRegSlot:       map[int]string{},
		fpParams:       map[int64]FrameSlot{},
		fpParamAlloca:  map[int64]string{},
		fpResAllocaOff: map[int64]string{},
		fpResAllocaIdx: map[int]string{},
		fpResWritten:   map[int]bool{},
		fpResAddrTaken: map[int]bool{},
		blockByIdx:     map[int]int{},
	}
	for _, s := range sig.Frame.Params {
		c.fpParams[s.Offset] = s
	}
	c.continuations = make(map[string]x86Continuation, len(fn.x86ContinuationAddresses))
	for symbol, target := range fn.x86ContinuationAddresses {
		target.root = resolve(target.root)
		c.continuations[resolve(symbol)] = target
	}
	c.indirectLabels = fn.x86IndirectLabels
	c.fpResults = append([]FrameSlot(nil), sig.Frame.Results...)
	base := 0
	for i, blk := range c.blocks {
		c.blockBase = append(c.blockBase, base)
		c.blockByIdx[base] = i
		base += len(blk.instrs)
	}
	return c
}

func (c *amd64Ctx) useHardwareX87() bool {
	return c.x87Mode != X87Software
}

func (c *amd64Ctx) emitSourceComment(ins Instr) {
	if !c.annotate {
		return
	}
	emitIRSourceComment(c.b, ins.Raw)
}

func (c *amd64Ctx) newTmp() string {
	c.tmp++
	return fmt.Sprintf("t%d", c.tmp)
}

func (c *amd64Ctx) slotName(r Reg) string {
	return "%" + amd64LLVMBlockName("reg_"+string(r))
}

func (c *amd64Ctx) xSlotName(i int) string {
	return fmt.Sprintf("%%x%d", i)
}

func amd64ParseXReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "X") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "X"))
	if err != nil || n < 0 || n > 31 {
		return 0, false
	}
	return n, true
}

func amd64ParseYReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "Y") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "Y"))
	if err != nil || n < 0 || n > 31 {
		return 0, false
	}
	return n, true
}

func amd64ParseZReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "Z") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "Z"))
	if err != nil || n < 0 || n > 31 {
		return 0, false
	}
	return n, true
}

func amd64ParseKReg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "K") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "K"))
	if err != nil || n < 0 || n > 7 {
		return 0, false
	}
	return n, true
}

func amd64ParseX87Reg(r Reg) (idx int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if !strings.HasPrefix(s, "F") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "F"))
	if err != nil || n < 0 || n > 7 {
		return 0, false
	}
	return n, true
}

func (c *amd64Ctx) scanUsedRegs() {
	markReg := func(r Reg) {
		if r == "" {
			return
		}
		// Byte aliases are read and written through their containing GP slot.
		if base, _, ok := amd64ByteAlias(r); ok {
			r = base
		}
		if idx, ok := amd64ParseXReg(r); ok {
			c.usedXRegs[idx] = true
			return
		}
		if idx, ok := amd64ParseYReg(r); ok {
			c.usedYRegs[idx] = true
			return
		}
		if idx, ok := amd64ParseZReg(r); ok {
			c.usedZRegs[idx] = true
			return
		}
		if idx, ok := amd64ParseKReg(r); ok {
			c.usedKRegs[idx] = true
			return
		}
		if _, ok := amd64ParseX87Reg(r); ok {
			c.usedX87 = true
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

	for _, blk := range c.blocks {
		for _, ins := range blk.instrs {
			op := strings.ToUpper(string(ins.Op))
			if dot := strings.IndexByte(op, '.'); dot >= 0 {
				op = op[:dot]
			}
			if (op == "CVTPS2PL" || op == "CVTTPS2PL") && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
				if _, mmx := amd64ParseMReg(ins.Args[1].Reg); mmx {
					c.mmxConversionSlot = "%mmx_conversion_result"
				}
			}
			if isX87Op(Op(op)) {
				c.usedX87 = true
				if op == "FMOVVP" {
					c.usesX87Convert = true
				}
			}
			if op == "LAHF" || op == "SAHF" {
				markReg(AX)
			}
			if spec, ok := amd64ImplicitSystemSpecs[Op(op)]; ok {
				registers := spec.inputs | spec.outputs
				if registers&amd64ImplicitAX != 0 {
					markReg(AX)
				}
				if registers&amd64ImplicitCX != 0 {
					markReg(CX)
				}
				if registers&amd64ImplicitDX != 0 {
					markReg(DX)
				}
			}
			if spec, ok := amd64RTMSpecs[Op(op)]; ok && spec.outputAX {
				markReg(AX)
			}
			if spec, ok := amd64SystemTransferSpecs[Op(op)]; ok {
				if spec.inputs&amd64SystemTransferCX != 0 {
					markReg(CX)
				}
				if spec.inputs&amd64SystemTransferDX != 0 {
					markReg(DX)
				}
				if c.goarch != "386" && spec.inputs&amd64SystemTransferR11 != 0 {
					markReg(Reg("R11"))
				}
			}
			if _, ok := amd64LeaveSpecs[Op(op)]; ok {
				markReg(BP)
				markReg(SP)
			}
			if op == "XLAT" {
				markReg(AX)
				markReg(BX)
			}
			if c.goarch == "386" {
				switch op {
				case "PUSHW", "POPW", "PUSHFW", "POPFW", "PUSHL", "POPL", "PUSHFL", "POPFL", "PUSHAL", "POPAL", "ADJSP":
					markReg(SP)
				}
			}
			for _, arg := range ins.Args {
				markOp(arg)
			}
			if _, fourSource := amd64FourSourceSpecs[Op(op)]; fourSource && len(ins.Args) >= 2 && ins.Args[1].Kind == OpRegList && len(ins.Args[1].RegList) != 0 {
				first := ins.Args[1].RegList[0]
				if index, ok := amd64ParseXReg(first); ok {
					base := index &^ 3
					for register := base; register < base+4; register++ {
						markReg(Reg(fmt.Sprintf("X%d", register)))
					}
				} else if index, ok := amd64ParseZReg(first); ok {
					base := index &^ 3
					for register := base; register < base+4; register++ {
						markReg(Reg(fmt.Sprintf("Z%d", register)))
					}
				}
			}
			if len(ins.Args) == 1 && ins.Args[0].Kind == OpReg {
				if spec, ok := x86UnaryYmbSpecs[Op(op)]; ok {
					markReg(amd64YmbEffectiveRegister(ins.Args[0].Reg, spec.bits))
				}
			}
		}
	}

	// Ensure a few common regs exist even if only used implicitly by helpers.
	markReg(AX)

	// Ensure arg regs exist for ABIInternal-style stdlib asm. This matters for:
	//   - functions like runtime·cmpstring<ABIInternal> that tail-call helpers
	//     without touching all argument regs (e.g. BX), and
	//   - helpers that expect words of an aggregate arg (slice/string) in
	//     consecutive registers.
	if len(c.sig.ArgRegs) > 0 {
		for i := 0; i < len(c.sig.Args) && i < len(c.sig.ArgRegs); i++ {
			markReg(c.sig.ArgRegs[i])
		}
		return
	}
	goABI := []Reg{AX, BX, CX, DI, SI, Reg("R8"), Reg("R9"), Reg("R10"), Reg("R11")}
	n := 0
	for _, ty := range c.sig.Args {
		if fields, ok := parseLiteralStructFields(ty); ok && literalFieldsAllScalar(fields) {
			n += len(fields)
		} else {
			n++
		}
	}
	for i := 0; i < n && i < len(goABI); i++ {
		markReg(goABI[i])
	}
}

func (c *amd64Ctx) emitEntryAllocas() error {
	c.scanUsedRegs()

	regs := make([]string, 0, len(c.usedRegs))
	for r := range c.usedRegs {
		regs = append(regs, string(r))
	}
	sort.Strings(regs)

	c.b.WriteString(amd64LLVMBlockName("entry") + ":\n")
	if c.mmxConversionSlot != "" {
		fmt.Fprintf(c.b, "  %s = alloca i64, align 8\n", c.mmxConversionSlot)
	}
	for _, rs := range regs {
		r := Reg(rs)
		name := c.slotName(r)
		c.regSlot[r] = name
		fmt.Fprintf(c.b, "  %s = alloca i64\n", name)
		fmt.Fprintf(c.b, "  store i64 0, ptr %s\n", name)
	}
	if spSlot, ok := c.regSlot[SP]; ok {
		minOff, maxOff := c.stackOffsetRange()
		var movement int64
		if c.goarch == "386" {
			var err error
			movement, err = c.stackMovementBudget()
			if err != nil {
				return err
			}
		}
		minOff -= movement
		maxOff += movement
		const guard = int64(64)
		bias := guard - minOff
		size := bias + maxOff + guard
		if size < 256 {
			size = 256
		}
		c.localStackSlot = "%local_stack"
		fmt.Fprintf(c.b, "  %s = alloca [%d x i8]\n", c.localStackSlot, size)
		base := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds [%d x i8], ptr %s, i32 0, i64 %d\n", base, size, c.localStackSlot, bias)
		addr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", addr, base)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", addr, spSlot)
	}

	xIdx := make([]int, 0, len(c.usedXRegs))
	for i := range c.usedXRegs {
		xIdx = append(xIdx, i)
	}
	sort.Ints(xIdx)
	for _, i := range xIdx {
		name := c.xSlotName(i)
		c.xRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca <16 x i8>\n", name)
		fmt.Fprintf(c.b, "  store <16 x i8> zeroinitializer, ptr %s\n", name)
	}

	yIdx := make([]int, 0, len(c.usedYRegs))
	for i := range c.usedYRegs {
		yIdx = append(yIdx, i)
	}
	sort.Ints(yIdx)
	for _, i := range yIdx {
		name := fmt.Sprintf("%%y%d", i)
		c.yRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca <32 x i8>\n", name)
		fmt.Fprintf(c.b, "  store <32 x i8> zeroinitializer, ptr %s\n", name)
	}

	zIdx := make([]int, 0, len(c.usedZRegs))
	for i := range c.usedZRegs {
		zIdx = append(zIdx, i)
	}
	sort.Ints(zIdx)
	for _, i := range zIdx {
		name := fmt.Sprintf("%%z%d", i)
		c.zRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca <64 x i8>\n", name)
		fmt.Fprintf(c.b, "  store <64 x i8> zeroinitializer, ptr %s\n", name)
	}

	kIdx := make([]int, 0, len(c.usedKRegs))
	for i := range c.usedKRegs {
		kIdx = append(kIdx, i)
	}
	sort.Ints(kIdx)
	for _, i := range kIdx {
		name := fmt.Sprintf("%%k%d", i)
		c.kRegSlot[i] = name
		fmt.Fprintf(c.b, "  %s = alloca i64\n", name)
		fmt.Fprintf(c.b, "  store i64 0, ptr %s\n", name)
	}
	if c.usedX87 {
		for i := range c.x87Slot {
			name := fmt.Sprintf("%%x87_f%d", i)
			c.x87Slot[i] = name
			fmt.Fprintf(c.b, "  %s = alloca double\n", name)
			fmt.Fprintf(c.b, "  store double 0.000000e+00, ptr %s\n", name)
		}
		c.x87ControlSlot = "%x87_control"
		c.x87StatusSlot = "%x87_status"
		fmt.Fprintf(c.b, "  %s = alloca i16\n", c.x87ControlSlot)
		fmt.Fprintf(c.b, "  store i16 895, ptr %s\n", c.x87ControlSlot) // 0x037f
		fmt.Fprintf(c.b, "  %s = alloca i16\n", c.x87StatusSlot)
		fmt.Fprintf(c.b, "  store i16 0, ptr %s\n", c.x87StatusSlot)
		if c.useHardwareX87() && c.usesX87Convert {
			c.x87IntegerSlot = "%x87_hw_integer"
			fmt.Fprintf(c.b, "  %s = alloca i64\n", c.x87IntegerSlot)
		}
	}
	c.flagsZSlot = "%flags_z"
	c.flagsSltSlot = "%flags_slt"
	c.flagsCFSlot = "%flags_cf"
	c.flagsPFSlot = "%flags_pf"
	c.flagsOFSlot = "%flags_of"
	c.directionSlot = "%direction_backward"
	if c.goarch == "386" {
		c.flagsIDSlot = "%flags_id"
	}
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsZSlot)
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsPFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
	fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsOFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	if c.flagsIDSlot != "" {
		fmt.Fprintf(c.b, "  %s = alloca i1\n", c.flagsIDSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsIDSlot)
	}
	if c.directionSlot != "" {
		fmt.Fprintf(c.b, "  %s = alloca i1\n", c.directionSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.directionSlot)
	}

	// Virtual stack for stack-manipulation instructions used by some stdlib asm
	// stubs (e.g. syscall rawVfork paths using POPQ/PUSHQ around SYSCALL).
	// We do not model host stack memory directly; this local stack keeps
	// lowering deterministic and avoids invalid memory accesses in IR.
	c.vstackSlot = "%virt_stack"
	c.vspSlot = "%virt_sp"
	fmt.Fprintf(c.b, "  %s = alloca [64 x i64]\n", c.vstackSlot)
	fmt.Fprintf(c.b, "  store [64 x i64] zeroinitializer, ptr %s\n", c.vstackSlot)
	fmt.Fprintf(c.b, "  %s = alloca i64\n", c.vspSlot)
	// Seed one synthetic return-address slot so an initial POPQ yields 0 and
	// subsequent PUSHQ can round-trip through the virtual stack.
	fmt.Fprintf(c.b, "  store i64 1, ptr %s\n", c.vspSlot)

	if c.goarch == "386" {
		if err := c.emit386ClassicFrame(); err != nil {
			return err
		}
	} else {
		// Named FP parameters have mutable frame-slot semantics in Go assembly.
		// Keep shadow storage even though LLVM function arguments are SSA values;
		// assembly kernels commonly advance slice pointers by writing base+off(FP)
		// and reading the updated value in a later loop iteration.
		for _, slot := range c.sig.Frame.Params {
			if slot.Index < 0 || slot.Index >= len(c.sig.Args) {
				return fmt.Errorf("FP frame slot: invalid arg index %d at +%d(FP)", slot.Index, slot.Offset)
			}
			name := amd64FPParamSlotName(slot.Offset)
			c.fpParamAlloca[slot.Offset] = name
			value := fmt.Sprintf("%%arg%d", slot.Index)
			if fields := frameSlotFields(slot); len(fields) != 0 {
				extracted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s%s\n", extracted, c.sig.Args[slot.Index], value, frameSlotExtractSuffix(slot))
				value = "%" + extracted
			}
			fmt.Fprintf(c.b, "  %s = alloca %s\n", name, slot.Type)
			fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", slot.Type, value, name)
		}
		for _, r := range c.fpResults {
			name := fmt.Sprintf("%%fp_ret_%d", r.Index)
			c.fpResAllocaIdx[r.Index] = name
			c.fpResAllocaOff[r.Offset] = name
			fmt.Fprintf(c.b, "  %s = alloca %s\n", name, r.Type)
			fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", r.Type, llvmZeroValue(r.Type), name)
		}
	}

	// Map LLVM args -> simulated registers for ABIInternal-ish entrypoints and
	// for helper<> bodies with explicit ArgRegs.
	if len(c.sig.ArgRegs) > 0 {
		for i := 0; i < len(c.sig.Args) && i < len(c.sig.ArgRegs); i++ {
			r := c.sig.ArgRegs[i]
			slot, ok := c.regSlot[r]
			if !ok {
				continue
			}
			arg := fmt.Sprintf("%%arg%d", i)
			v, ok, err := amd64ValueAsI64(c, c.sig.Args[i], arg)
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

	// Default Go internal ABI integer argument registers (ssa/opGen.go).
	goABI := []Reg{AX, BX, CX, DI, SI, Reg("R8"), Reg("R9"), Reg("R10"), Reg("R11")}
	regIdx := 0
	for ai := 0; ai < len(c.sig.Args) && regIdx < len(goABI); ai++ {
		arg := fmt.Sprintf("%%arg%d", ai)
		argTy := c.sig.Args[ai]
		if fields, ok := parseLiteralStructFields(argTy); ok && literalFieldsAllScalar(fields) {
			for fi, fTy := range fields {
				if regIdx >= len(goABI) {
					break
				}
				r := goABI[regIdx]
				regIdx++
				slot, ok := c.regSlot[r]
				if !ok {
					continue
				}
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", t, argTy, arg, fi)
				v, ok, err := amd64ValueAsI64(c, fTy, "%"+t)
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

		r := goABI[regIdx]
		regIdx++
		slot, ok := c.regSlot[r]
		if !ok {
			continue
		}
		v, ok, err := amd64ValueAsI64(c, argTy, arg)
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

func amd64FPParamSlotName(off int64) string {
	if off < 0 {
		return fmt.Sprintf("%%fp_arg_n%d", -off)
	}
	return fmt.Sprintf("%%fp_arg_%d", off)
}

func x86FrameTypeSize(ty LLVMType) int64 {
	switch ty {
	case I1, I8:
		return 1
	case I16:
		return 2
	case I32, Ptr, LLVMType("float"):
		return 4
	case I64, LLVMType("double"):
		return 8
	default:
		// FrameLayout normally contains scalar parts. Keep enough room for an
		// unexpected aggregate so address formation remains within the alloca.
		return 16
	}
}

func (c *amd64Ctx) classicFrameRange() (minOff, maxOff int64, used bool) {
	add := func(off, size int64) {
		if !used || off < minOff {
			minOff = off
		}
		if end := off + size; !used || end > maxOff {
			maxOff = end
		}
		used = true
	}
	for _, slot := range c.sig.Frame.Params {
		add(slot.Offset, x86FrameTypeSize(slot.Type))
	}
	for _, slot := range c.fpResults {
		add(slot.Offset, x86FrameTypeSize(slot.Type))
	}
	for _, block := range c.blocks {
		for _, ins := range block.instrs {
			for _, arg := range ins.Args {
				if arg.Kind == OpFP || arg.Kind == OpFPAddr {
					add(arg.FPOffset, 16)
				}
			}
		}
	}
	return minOff, maxOff, used
}

func (c *amd64Ctx) classicFramePtr(off int64) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds [%d x i8], ptr %s, i32 0, i64 %d\n", t, c.classicSize, c.classicFrame, c.classicBias+off)
	return "%" + t
}

func (c *amd64Ctx) emit386ClassicFrame() error {
	minOff, maxOff, used := c.classicFrameRange()
	if !used {
		return nil
	}
	c.classicBias = -minOff
	c.classicSize = maxOff - minOff
	c.classicFrame = "%classic_frame"
	fmt.Fprintf(c.b, "  %s = alloca [%d x i8]\n", c.classicFrame, c.classicSize)

	for _, slot := range c.sig.Frame.Params {
		if slot.Index < 0 || slot.Index >= len(c.sig.Args) {
			return fmt.Errorf("FP frame slot: invalid arg index %d at +%d(FP)", slot.Index, slot.Offset)
		}
		value := fmt.Sprintf("%%arg%d", slot.Index)
		if fields := frameSlotFields(slot); len(fields) != 0 {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s%s\n", extracted, c.sig.Args[slot.Index], value, frameSlotExtractSuffix(slot))
			value = "%" + extracted
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", slot.Type, value, c.classicFramePtr(slot.Offset))
	}
	for _, slot := range c.fpResults {
		ptr := c.classicFramePtr(slot.Offset)
		c.fpResAllocaIdx[slot.Index] = ptr
		c.fpResAllocaOff[slot.Offset] = ptr
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", slot.Type, llvmZeroValue(slot.Type), ptr)
	}
	return nil
}

func (c *amd64Ctx) stackOffsetRange() (minOff, maxOff int64) {
	for _, block := range c.blocks {
		for _, ins := range block.instrs {
			for _, arg := range ins.Args {
				if arg.Kind != OpMem || arg.Mem.Base != SP {
					continue
				}
				if arg.Mem.Off < minOff {
					minOff = arg.Mem.Off
				}
				// Reserve enough room for the largest scalar operation lowered here.
				if end := arg.Mem.Off + 16; end > maxOff {
					maxOff = end
				}
			}
		}
	}
	return minOff, maxOff
}

const max386LocalStackMovement = int64(1 << 20)

func (c *amd64Ctx) stackMovementBudget() (int64, error) {
	// The local stack models bounded movement relative to its initial SP. Some
	// runtime routines explicitly rebase SP from a saved context; those writes
	// intentionally leave this local object and do not contribute to its size.
	var total int64
	add := func(delta int64, ins Instr) error {
		if delta < 0 || delta > max386LocalStackMovement-total {
			return fmt.Errorf("386 local stack movement exceeds %d bytes at %q", max386LocalStackMovement, ins.Raw)
		}
		total += delta
		return nil
	}
	for _, block := range c.blocks {
		for _, ins := range block.instrs {
			switch strings.ToUpper(string(ins.Op)) {
			case "PUSHL", "POPL", "PUSHFL", "POPFL":
				if err := add(4, ins); err != nil {
					return 0, err
				}
			case "PUSHW", "POPW", "PUSHFW", "POPFW":
				if err := add(2, ins); err != nil {
					return 0, err
				}
			case "PUSHAL", "POPAL":
				if err := add(32, ins); err != nil {
					return 0, err
				}
			case "ADJSP":
				if len(ins.Args) == 1 && ins.Args[0].Kind == OpImm {
					if err := add(abs386StackAdjustment(int64(ins.Args[0].Imm)), ins); err != nil {
						return 0, err
					}
				}
			case "ADDL", "SUBL":
				if is386SPDestination(ins) && len(ins.Args) == 2 && ins.Args[0].Kind == OpImm {
					if err := add(abs386StackAdjustment(int64(ins.Args[0].Imm)), ins); err != nil {
						return 0, err
					}
				}
			case "INCL", "DECL":
				if is386SPDestination(ins) {
					if err := add(1, ins); err != nil {
						return 0, err
					}
				}
			case "INCW", "DECW":
				if is386SPDestination(ins) {
					// A low-word wrap can move the modeled SP by as much as 65535.
					if err := add(65535, ins); err != nil {
						return 0, err
					}
				}
			case "ADDW", "SUBW":
				if is386SPDestination(ins) {
					// A low-word update can move the modeled SP by up to 65535.
					if err := add(65535, ins); err != nil {
						return 0, err
					}
				}
			case "ANDL":
				if movement, ok := bounded386SPAndMovement(ins); ok {
					if err := add(movement, ins); err != nil {
						return 0, err
					}
				}
			case "LEAL":
				if is386SPDestination(ins) && len(ins.Args) == 2 && ins.Args[0].Kind == OpMem &&
					ins.Args[0].Mem.Base == SP && ins.Args[0].Mem.Index == "" {
					if err := add(abs386StackAdjustment(ins.Args[0].Mem.Off), ins); err != nil {
						return 0, err
					}
				}
			}
		}
	}
	return total, nil
}

func abs386StackAdjustment(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func is386SPDestination(ins Instr) bool {
	if len(ins.Args) == 0 {
		return false
	}
	dst := ins.Args[len(ins.Args)-1]
	return dst.Kind == OpReg && dst.Reg == SP
}

func bounded386SPAndMovement(ins Instr) (int64, bool) {
	if !is386SPDestination(ins) || len(ins.Args) != 2 || ins.Args[0].Kind != OpImm {
		return 0, false
	}
	// ANDL alignment masks used by the Go runtime only clear low address bits.
	// The bitwise complement is the greatest possible downward adjustment.
	movement := int64(^uint32(ins.Args[0].Imm))
	return movement, movement <= max386LocalStackMovement
}

func models386SPWrite(ins Instr) bool {
	op := strings.ToUpper(string(ins.Op))
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		op = op[:dot]
	}
	if op == "MOVQ" && len(ins.Args) == 2 && ins.Args[1].Kind == OpReg && ins.Args[1].Reg == SP && ins.Args[0].Kind == OpReg {
		class, _, special := x86MachineRegister(ins.Args[0].Reg)
		return special && (class == "cr" || class == "dr")
	}
	if len(ins.Args) == 1 && ins.Args[0].Kind == OpReg {
		if spec, ok := x86UnaryYmbSpecs[Op(op)]; ok && spec.bits != 64 {
			return amd64YmbEffectiveRegister(ins.Args[0].Reg, spec.bits) == SP
		}
	}
	if !is386SPDestination(ins) {
		return false
	}
	if _, ok := amd64BMI2ShiftSpecs[op]; ok {
		return true
	}
	switch op {
	case "MOVL", "ADDW", "SUBW", "ADCW", "SBBW", "ADDL", "SUBL", "ADCL", "SBBL", "ADCXL", "ADOXL", "LEAW", "LEAL", "POPW", "POPL",
		"CRC32B", "CRC32W", "CRC32L",
		"CMPXCHGW", "CMPXCHGL",
		"POPCNTW", "POPCNTL", "TZCNTW", "TZCNTL", "LZCNTW", "LZCNTL", "PMOVMSKB", "VPMOVMSKB",
		"BEXTRL", "BEXTRQ", "BZHIL", "BZHIQ", "BLSIL", "BLSIQ", "BLSMSKL", "BLSMSKQ", "BLSRL", "BLSRQ",
		"ANDNL", "ANDNQ",
		"RORXL", "RORXQ",
		"PDEPL", "PDEPQ", "PEXTL", "PEXTQ",
		"CVTSS2SL", "CVTSD2SL", "CVTTSS2SL", "CVTTSD2SL",
		"VCVTSS2SI", "VCVTSD2SI", "VCVTTSS2SI", "VCVTTSD2SI",
		"VCVTSS2USIL", "VCVTSD2USIL", "VCVTTSS2USIL", "VCVTTSD2USIL":
		// These are the direct SP forms used by the official 386 corpus. MOVL
		// and non-SP LEAL rebase to an explicitly supplied stack context;
		// arithmetic and SP-relative LEAL retain the current stack model.
		return true
	case "RDPID":
		return len(ins.Args) == 1 && ins.Args[0].Kind == OpReg && ins.Args[0].Reg == SP
	case "RCLW", "RCLL", "RCRW", "RCRL", "ROLW", "ROLL", "RORW", "RORL", "SARW", "SARL",
		"SALW", "SALL", "SHLW", "SHLL", "SHRW", "SHRL":
		return true
	case "INCW", "DECW", "INCL", "DECL":
		return true
	case "BTCW", "BTCL", "BTRW", "BTRL", "BTSW", "BTSL":
		return true
	case "SLDTW", "SLDTL", "SMSWW", "SMSWL", "STRW", "STRL":
		// Go's Yml destination class includes SP in 386 mode. These system
		// instructions write their result directly to that destination.
		return true
	case "LARW", "LARL", "LSLW", "LSLL":
		// LAR/LSL use the same Yrl destination class, including SP.
		return true
	case "LFSW", "LFSL", "LGSW", "LGSL", "LSSW", "LSSL":
		// Far-pointer loads also use Yrl, including SP, for their offset.
		return true
	case "RDFSBASEL", "RDGSBASEL":
		// The 386 FSGSBASE read forms use Yrl destinations, including SP.
		return true
	case "MOVBWSX", "MOVBWZX", "MOVBLSX", "MOVBLZX",
		"MOVWLSX", "MOVWLZX", "MOVLQZX", "MOVSWW", "MOVZWW":
		return true
	case "KMOVB", "KMOVW", "KMOVD", "KMOVQ":
		return len(ins.Args) == 2 && amd64IsKOperand(ins.Args[0])
	case "ANDL":
		_, ok := bounded386SPAndMovement(ins)
		return ok
	default:
		return false
	}
}

func (c *amd64Ctx) pushI64(v string) {
	sp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", sp, c.vspSlot)
	full := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp uge i64 %%%s, 64\n", full, sp)
	idx := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 63, i64 %%%s\n", idx, full, sp)
	ptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds [64 x i64], ptr %s, i32 0, i64 %%%s\n", ptr, c.vstackSlot, idx)
	fmt.Fprintf(c.b, "  store i64 %s, ptr %%%s\n", v, ptr)
	inc := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, 1\n", inc, sp)
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 64, i64 %%%s\n", next, full, inc)
	fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", next, c.vspSlot)
}

func (c *amd64Ctx) popI64() string {
	sp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", sp, c.vspSlot)
	empty := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, 0\n", empty, sp)
	dec := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, 1\n", dec, sp)
	idx := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 0, i64 %%%s\n", idx, empty, dec)
	fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", idx, c.vspSlot)
	ptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds [64 x i64], ptr %s, i32 0, i64 %%%s\n", ptr, c.vstackSlot, idx)
	val := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %%%s\n", val, ptr)
	return "%" + val
}

func (c *amd64Ctx) pushI16(v string) error {
	sp, err := c.loadReg(SP)
	if err != nil {
		return err
	}
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 2\n", next, sp)
	if err := c.storeRegUnchecked(SP, "%"+next); err != nil {
		return err
	}
	p := c.ptrFromAddrI64("%" + next)
	fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", v, p)
	return nil
}

func (c *amd64Ctx) popI16() (string, error) {
	sp, err := c.loadReg(SP)
	if err != nil {
		return "", err
	}
	p := c.ptrFromAddrI64(sp)
	v := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s, align 1\n", v, p)
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, 2\n", next, sp)
	if err := c.storeRegUnchecked(SP, "%"+next); err != nil {
		return "", err
	}
	return "%" + v, nil
}

func (c *amd64Ctx) pushI32(v string) error {
	sp, err := c.loadReg(SP)
	if err != nil {
		return err
	}
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 4\n", next, sp)
	if err := c.storeRegUnchecked(SP, "%"+next); err != nil {
		return err
	}
	p := c.ptrFromAddrI64("%" + next)
	fmt.Fprintf(c.b, "  store i32 %s, ptr %s, align 1\n", v, p)
	return nil
}

func (c *amd64Ctx) popI32() (string, error) {
	sp, err := c.loadReg(SP)
	if err != nil {
		return "", err
	}
	p := c.ptrFromAddrI64(sp)
	v := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", v, p)
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, 4\n", next, sp)
	if err := c.storeRegUnchecked(SP, "%"+next); err != nil {
		return "", err
	}
	return "%" + v, nil
}

func amd64ValueAsI64(c *amd64Ctx, ty LLVMType, v string) (out string, ok bool, err error) {
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
	default:
		return "", false, nil
	}
}

func amd64ByteAlias(rr Reg) (base Reg, shift uint, ok bool) {
	switch rr {
	case AL:
		return AX, 0, true
	case AH:
		return AX, 8, true
	case BL:
		return BX, 0, true
	case BH:
		return BX, 8, true
	case CL:
		return CX, 0, true
	case CH:
		return CX, 8, true
	case DL:
		return DX, 0, true
	case DH:
		return DX, 8, true
	case BPB:
		return BP, 0, true
	case SIB:
		return SI, 0, true
	case DIB:
		return DI, 0, true
	case R8B:
		return Reg("R8"), 0, true
	case R9B:
		return Reg("R9"), 0, true
	case R10B:
		return Reg("R10"), 0, true
	case R11B:
		return Reg("R11"), 0, true
	case R12B:
		return Reg("R12"), 0, true
	case R13B:
		return Reg("R13"), 0, true
	case R14B:
		return Reg("R14"), 0, true
	case R15B:
		return Reg("R15"), 0, true
	default:
		return "", 0, false
	}
}

func amd64FullRegBase(r Reg) (Reg, bool) {
	if base, _, ok := amd64ByteAlias(r); ok {
		return base, true
	}
	if r == "" || r == PC || r == ZR {
		return "", false
	}
	if _, ok := amd64ParseXReg(r); ok {
		return "", false
	}
	if _, ok := amd64ParseYReg(r); ok {
		return "", false
	}
	if _, ok := amd64ParseZReg(r); ok {
		return "", false
	}
	if _, ok := amd64ParseKReg(r); ok {
		return "", false
	}
	return r, true
}

func amd64ByteRegBase(r Reg) (base Reg, shift uint, ok bool) {
	if base, shift, ok := amd64ByteAlias(r); ok {
		return base, shift, true
	}
	base, ok = amd64FullRegBase(r)
	if !ok {
		return "", 0, false
	}
	return base, 0, true
}

func (c *amd64Ctx) loadReg(r Reg) (string, error) {
	// Model byte aliases used by stdlib asm. Reads return the selected byte as a
	// zero-extended i64.
	if base, shift, ok := amd64ByteAlias(r); ok {
		v, err := c.loadReg(base)
		if err != nil {
			return "", err
		}
		if shift != 0 {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", t, v, shift)
			v = "%" + t
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 255\n", t, v)
		return "%" + t, nil
	}
	slot, ok := c.regSlot[r]
	if !ok {
		return "0", nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *amd64Ctx) storeReg(r Reg, v string) error {
	if c.goarch == "386" && r == SP && !c.allowSPWrite {
		return fmt.Errorf("386 direct SP write is unsupported; use ADJSP or a modeled stack instruction")
	}
	return c.storeRegUnchecked(r, v)
}

func (c *amd64Ctx) storeRegUnchecked(r Reg, v string) error {
	// See loadReg for byte-alias handling.
	if base, shift, ok := amd64ByteAlias(r); ok {
		cur, err := c.loadReg(base)
		if err != nil {
			return err
		}
		mask := int64(0xff) << shift
		cleared := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", cleared, cur, ^mask)
		byteVal := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, 255\n", byteVal, v)
		ins := "%" + byteVal
		if shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", shifted, byteVal, shift)
			ins = "%" + shifted
		}
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, cleared, ins)
		r = base
		v = "%" + merged
	}
	slot, ok := c.regSlot[r]
	if !ok {
		return nil
	}
	fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
	return nil
}

func (c *amd64Ctx) storeRegSized(r Reg, ty LLVMType, v string) error {
	switch ty {
	case I8:
		base, shift, ok := amd64ByteRegBase(r)
		if !ok {
			return fmt.Errorf("not a GP reg for i8 store: %s", r)
		}
		cur, err := c.loadReg(base)
		if err != nil {
			return err
		}
		mask := int64(0xff) << shift
		cleared := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", cleared, cur, ^mask)
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i64\n", ext, v)
		ins := "%" + ext
		if shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", shifted, ext, shift)
			ins = "%" + shifted
		}
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, cleared, ins)
		return c.storeReg(base, "%"+merged)
	case I16:
		base, ok := amd64FullRegBase(r)
		if !ok {
			return fmt.Errorf("not a GP reg for i16 store: %s", r)
		}
		cur, err := c.loadReg(base)
		if err != nil {
			return err
		}
		cleared := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", cleared, cur, ^int64(0xffff))
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i64\n", ext, v)
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", merged, cleared, ext)
		return c.storeReg(base, "%"+merged)
	case I32:
		base, ok := amd64FullRegBase(r)
		if !ok {
			return fmt.Errorf("not a GP reg for i32 store: %s", r)
		}
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", ext, v)
		return c.storeReg(base, "%"+ext)
	case I64:
		base, ok := amd64FullRegBase(r)
		if ok {
			return c.storeReg(base, v)
		}
		return c.storeReg(r, v)
	default:
		return fmt.Errorf("unsupported sized reg store %s to %s", ty, r)
	}
}

func (c *amd64Ctx) loadX(r Reg) (string, error) {
	idx, ok := amd64ParseXReg(r)
	if !ok {
		return "", fmt.Errorf("not an X reg: %s", r)
	}
	slot, ok := c.xRegSlot[idx]
	if !ok {
		return "zeroinitializer", nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *amd64Ctx) storeX(r Reg, v string) error {
	idx, ok := amd64ParseXReg(r)
	if !ok {
		return fmt.Errorf("not an X reg: %s", r)
	}
	slot, ok := c.xRegSlot[idx]
	if !ok {
		return nil
	}
	fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s\n", v, slot)
	return nil
}

func (c *amd64Ctx) loadY(r Reg) (string, error) {
	idx, ok := amd64ParseYReg(r)
	if !ok {
		return "", fmt.Errorf("not a Y reg: %s", r)
	}
	slot, ok := c.yRegSlot[idx]
	if !ok {
		return "zeroinitializer", nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <32 x i8>, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *amd64Ctx) storeY(r Reg, v string) error {
	if _, ok := amd64ParseYReg(r); !ok {
		return fmt.Errorf("not a Y reg: %s", r)
	}
	// A 256-bit VEX write also replaces X and clears the upper Z view.
	// Raw and named instructions must observe the same physical register.
	return c.storePackedMoveOperand(Operand{Kind: OpReg, Reg: r}, 32, v)
}

func (c *amd64Ctx) loadZ(r Reg) (string, error) {
	idx, ok := amd64ParseZReg(r)
	if !ok {
		return "", fmt.Errorf("not a Z reg: %s", r)
	}
	slot, ok := c.zRegSlot[idx]
	if !ok {
		return "zeroinitializer", nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <64 x i8>, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *amd64Ctx) storeZ(r Reg, v string) error {
	idx, ok := amd64ParseZReg(r)
	if !ok {
		return fmt.Errorf("not a Z reg: %s", r)
	}
	slot, ok := c.zRegSlot[idx]
	if !ok {
		return nil
	}
	fmt.Fprintf(c.b, "  store <64 x i8> %s, ptr %s\n", v, slot)
	return nil
}

func (c *amd64Ctx) loadK(r Reg) (string, error) {
	idx, ok := amd64ParseKReg(r)
	if !ok {
		return "", fmt.Errorf("not a K reg: %s", r)
	}
	slot, ok := c.kRegSlot[idx]
	if !ok {
		return "0", nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", t, slot)
	return "%" + t, nil
}

func (c *amd64Ctx) storeK(r Reg, v string) error {
	idx, ok := amd64ParseKReg(r)
	if !ok {
		return fmt.Errorf("not a K reg: %s", r)
	}
	slot, ok := c.kRegSlot[idx]
	if !ok {
		return nil
	}
	fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", v, slot)
	return nil
}

func (c *amd64Ctx) setZFlagFromI64(v string) {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", t, v)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", t, c.flagsZSlot)
}

func (c *amd64Ctx) setZSFlagsFromI64(v string) {
	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", z, v)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
	slt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, 0\n", slt, v)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", slt, c.flagsSltSlot)
	c.setParityFlagSized(I64, v)
}

func (c *amd64Ctx) setZSFlagsFromI32(v string) {
	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", z, v)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
	slt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, 0\n", slt, v)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", slt, c.flagsSltSlot)
	c.setParityFlagSized(I32, v)
}

func (c *amd64Ctx) setParityFlagSized(ty LLVMType, v string) {
	low := v
	if ty != I8 {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to i8\n", truncated, ty, v)
		low = "%" + truncated
	}
	shift4 := c.newTmp()
	fold4 := c.newTmp()
	shift2 := c.newTmp()
	fold2 := c.newTmp()
	shift1 := c.newTmp()
	fold1 := c.newTmp()
	bit := c.newTmp()
	parity := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i8 %s, 4\n", shift4, low)
	fmt.Fprintf(c.b, "  %%%s = xor i8 %s, %%%s\n", fold4, low, shift4)
	fmt.Fprintf(c.b, "  %%%s = lshr i8 %%%s, 2\n", shift2, fold4)
	fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, %%%s\n", fold2, fold4, shift2)
	fmt.Fprintf(c.b, "  %%%s = lshr i8 %%%s, 1\n", shift1, fold2)
	fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, %%%s\n", fold1, fold2, shift1)
	fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 1\n", bit, fold1)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", parity, bit)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", parity, c.flagsPFSlot)
}

func (c *amd64Ctx) setCmpFlags(a, b string) {
	// Plan 9 CMPQ uses source-destination order for flag interpretation here:
	// treat CMPQ a,b as deriving less-than from a<b.
	zt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, %s\n", zt, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zt, c.flagsZSlot)
	slt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %s, %s\n", slt, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", slt, c.flagsSltSlot)
	ult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", ult, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ult, c.flagsCFSlot)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", result, a, b)
	c.setParityFlagSized(I64, "%"+result)
}

func (c *amd64Ctx) loadFlag(slot string) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", t, slot)
	return "%" + t
}

func (c *amd64Ctx) fpParam(off int64) (slot FrameSlot, ok bool) {
	s, ok := c.fpParams[off]
	if !ok {
		return FrameSlot{}, false
	}
	return s, true
}

func (c *amd64Ctx) loadFPParamValue(slot FrameSlot) (string, error) {
	if slot.Index < 0 || slot.Index >= len(c.sig.Args) {
		return "", fmt.Errorf("FP read slot: invalid arg index %d at +%d(FP)", slot.Index, slot.Offset)
	}
	if c.classicFrame != "" {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", loaded, slot.Type, c.classicFramePtr(slot.Offset))
		return "%" + loaded, nil
	}
	if shadow := c.fpParamAlloca[slot.Offset]; shadow != "" {
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", loaded, slot.Type, shadow)
		return "%" + loaded, nil
	}
	value := fmt.Sprintf("%%arg%d", slot.Index)
	if fields := frameSlotFields(slot); len(fields) != 0 {
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s%s\n", extracted, c.sig.Args[slot.Index], value, frameSlotExtractSuffix(slot))
		value = "%" + extracted
	}
	return value, nil
}

func (c *amd64Ctx) fpResultAlloca(off int64) (string, LLVMType, bool) {
	s, ok := c.fpParams[off]
	_ = s
	name, ok := c.fpResAllocaOff[off]
	if !ok {
		return "", "", false
	}
	// Find the slot type.
	for _, r := range c.fpResults {
		if r.Offset == off {
			return name, r.Type, true
		}
	}
	return name, "", true
}

func (c *amd64Ctx) markFPResultAddrTaken(off int64) {
	for _, r := range c.fpResults {
		if r.Offset == off {
			c.fpResAddrTaken[r.Index] = true
			return
		}
	}
}

func (c *amd64Ctx) markFPResultWritten(off int64) {
	for _, r := range c.fpResults {
		if r.Offset == off {
			c.fpResWritten[r.Index] = true
			return
		}
	}
}

func (c *amd64Ctx) evalFPToI64(off int64) (string, error) {
	slot, ok := c.fpParam(off)
	if !ok {
		if c.goarch == "386" {
			for baseOff, candidate := range c.fpParams {
				if off != baseOff+4 || !isSplit64FrameType(candidate.Type) {
					continue
				}
				full, err := c.evalFPToI64(baseOff)
				if err != nil {
					return "", err
				}
				hi := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", hi, full)
				return "%" + hi, nil
			}
		}
		if alloca, ty, rok := c.fpResultAlloca(off); rok && ty != "" {
			ld := c.newTmp()
			align := ""
			if c.classicFrame != "" {
				align = ", align 1"
			}
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s%s\n", ld, ty, alloca, align)
			v := "%" + ld
			switch ty {
			case I64:
				return v, nil
			case I1:
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", z, v)
				return "%" + z, nil
			case I8:
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i64\n", z, v)
				return "%" + z, nil
			case I16:
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i64\n", z, v)
				return "%" + z, nil
			case I32:
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, v)
				return "%" + z, nil
			case Ptr:
				p := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", p, v)
				return "%" + p, nil
			}
		}
		if c.goarch == "386" {
			for _, candidate := range c.fpResults {
				if off != candidate.Offset+4 || !isSplit64FrameType(candidate.Type) {
					continue
				}
				full, err := c.evalFPToI64(candidate.Offset)
				if err != nil {
					return "", err
				}
				hi := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", hi, full)
				return "%" + hi, nil
			}
		}
		// Keep translating when FP offsets can't be recovered from signature
		// inference (common in low-level runtime assembly).
		return "0", nil
	}
	ty := slot.Type
	arg, err := c.loadFPParamValue(slot)
	if err != nil {
		return "", err
	}
	switch ty {
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, arg)
		return "%" + t, nil
	case I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", t, arg)
		return "%" + t, nil
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i64\n", t, arg)
		return "%" + t, nil
	case I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i64\n", t, arg)
		return "%" + t, nil
	case I32:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, arg)
		return "%" + t, nil
	case I64:
		return arg, nil
	case LLVMType("double"):
		// MOVQ from a float64 FP slot copies raw bits, not numeric conversion.
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, arg)
		return "%" + t, nil
	case LLVMType("float"):
		// MOVL/MOVQ from float32 slots use raw IEEE-754 bits.
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bits, arg)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, bits)
		return "%" + z, nil
	default:
		return "", fmt.Errorf("FP read unsupported type %q at +%d(FP)", ty, off)
	}
}

func amd64IntegerTypeBits(ty LLVMType) (int, bool) {
	switch ty {
	case I1:
		return 1, true
	case I8:
		return 8, true
	case I16:
		return 16, true
	case I32:
		return 32, true
	case I64:
		return 64, true
	default:
		return 0, false
	}
}

func amd64IntegerTypeForBits(bits int) LLVMType {
	switch bits {
	case 1:
		return I1
	case 8:
		return I8
	case 16:
		return I16
	case 32:
		return I32
	case 64:
		return I64
	default:
		return ""
	}
}

func (c *amd64Ctx) coerceFPStoreValue(from, to LLVMType, value string) (string, error) {
	if from == to {
		return value, nil
	}
	pointerBits := 64
	if c.goarch == "386" {
		pointerBits = 32
	}

	rawType := from
	rawValue := value
	switch from {
	case Ptr:
		rawType = amd64IntegerTypeForBits(pointerBits)
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to %s\n", cast, value, rawType)
		rawValue = "%" + cast
	case LLVMType("float"):
		rawType = I32
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", cast, value)
		rawValue = "%" + cast
	case LLVMType("double"):
		rawType = I64
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", cast, value)
		rawValue = "%" + cast
	default:
		if _, ok := amd64IntegerTypeBits(from); !ok {
			return "", fmt.Errorf("unsupported FP store source type %s", from)
		}
	}

	targetBits := 0
	switch to {
	case Ptr:
		targetBits = pointerBits
	case LLVMType("float"):
		targetBits = 32
	case LLVMType("double"):
		targetBits = 64
	default:
		var ok bool
		targetBits, ok = amd64IntegerTypeBits(to)
		if !ok {
			return "", fmt.Errorf("unsupported FP store destination type %s", to)
		}
	}

	fromBits, _ := amd64IntegerTypeBits(rawType)
	targetIntType := amd64IntegerTypeForBits(targetBits)
	if fromBits > targetBits {
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", cast, rawType, rawValue, targetIntType)
		rawType, rawValue = targetIntType, "%"+cast
	} else if fromBits < targetBits {
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", cast, rawType, rawValue, targetIntType)
		rawType, rawValue = targetIntType, "%"+cast
	}

	switch to {
	case Ptr:
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr %s %s to ptr\n", cast, rawType, rawValue)
		return "%" + cast, nil
	case LLVMType("float"), LLVMType("double"):
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", cast, rawType, rawValue, to)
		return "%" + cast, nil
	default:
		return rawValue, nil
	}
}

func (c *amd64Ctx) storeFPResult(off int64, ty LLVMType, v string) error {
	return c.storeFPResultWithMetadata(off, ty, v, "")
}

func (c *amd64Ctx) storeFPResultWithMetadata(off int64, ty LLVMType, v, metadata string) error {
	align := ""
	if c.classicFrame != "" {
		// The 386 ABI frame is a byte array, and FP offsets need not provide
		// the natural alignment required by the value stored in a slot.
		align = ", align 1"
	}
	if slot, ok := c.fpParams[off]; ok {
		ptr := c.fpParamAlloca[off]
		if c.classicFrame != "" {
			ptr = c.classicFramePtr(off)
		}
		if ptr == "" {
			return fmt.Errorf("missing mutable FP parameter slot at +%d(FP)", off)
		}
		value, err := c.coerceFPStoreValue(ty, slot.Type, v)
		if err != nil {
			return fmt.Errorf("FP parameter write type mismatch: have %s want %s at +%d(FP): %w", ty, slot.Type, off, err)
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s%s%s\n", slot.Type, value, ptr, align, metadata)
		return nil
	}
	if c.goarch == "386" && ty == I32 {
		for _, slot := range c.fpResults {
			if !isSplit64FrameType(slot.Type) ||
				(off != slot.Offset && off != slot.Offset+4) {
				continue
			}
			alloca := c.fpResAllocaIdx[slot.Index]
			old := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s%s\n", old, slot.Type, alloca, align)
			bits := "%" + old
			if slot.Type == LLVMType("double") {
				cast := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast double %%%s to i64\n", cast, old)
				bits = "%" + cast
			}
			cleared := c.newTmp()
			word := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", word, v)
			inserted := "%" + word
			if off == slot.Offset {
				fmt.Fprintf(c.b, "  %%%s = and i64 %s, -4294967296\n", cleared, bits)
			} else {
				fmt.Fprintf(c.b, "  %%%s = and i64 %s, 4294967295\n", cleared, bits)
				shifted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, 32\n", shifted, word)
				inserted = "%" + shifted
			}
			merged := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, cleared, inserted)
			if slot.Type == LLVMType("double") {
				cast := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to double\n", cast, merged)
				fmt.Fprintf(c.b, "  store double %%%s, ptr %s%s%s\n", cast, alloca, align, metadata)
			} else {
				fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s%s%s\n", merged, alloca, align, metadata)
			}
			c.fpResWritten[slot.Index] = true
			return nil
		}
	}
	alloca, slotTy, ok := c.fpResultAlloca(off)
	if !ok {
		return fmt.Errorf("unsupported FP write slot: +%d(FP)", off)
	}
	if slotTy != "" && slotTy != ty {
		if c.goarch == "386" && ty == I32 && slotTy == Ptr {
			p := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", p, v)
			fmt.Fprintf(c.b, "  store ptr %%%s, ptr %s%s%s\n", p, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		}
		if ty == I32 && slotTy == LLVMType("float") {
			cast := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to float\n", cast, v)
			fmt.Fprintf(c.b, "  store float %%%s, ptr %s%s%s\n", cast, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		}
		if ty == LLVMType("float") && slotTy == I32 {
			cast := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", cast, v)
			fmt.Fprintf(c.b, "  store i32 %%%s, ptr %s%s%s\n", cast, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		}
		intBits := func(t LLVMType) (int, bool) {
			switch t {
			case I1:
				return 1, true
			case I8:
				return 8, true
			case I16:
				return 16, true
			case I32:
				return 32, true
			case I64:
				return 64, true
			default:
				return 0, false
			}
		}
		if fromBits, okFrom := intBits(ty); okFrom {
			if toBits, okTo := intBits(slotTy); okTo {
				cast := v
				if fromBits > toBits {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", t, ty, v, slotTy)
					cast = "%" + t
				} else if fromBits < toBits {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", t, ty, v, slotTy)
					cast = "%" + t
				}
				fmt.Fprintf(c.b, "  store %s %s, ptr %s%s%s\n", slotTy, cast, alloca, align, metadata)
				c.markFPResultWritten(off)
				return nil
			}
		}
		if (ty == I64 || ty == LLVMType("double")) && slotTy == LLVMType("float") {
			secondAlloca, secondTy, secondOK := c.fpResultAlloca(off + 4)
			if !secondOK || secondTy != LLVMType("float") {
				return fmt.Errorf("FP write at +%d(FP) cannot split a 64-bit memory operand", off)
			}
			bits := v
			if ty == LLVMType("double") {
				cast := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", cast, v)
				bits = "%" + cast
			}
			low := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", low, bits)
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, 32\n", shifted, bits)
			high := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", high, shifted)
			lowFloat := c.newTmp()
			highFloat := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", lowFloat, low)
			fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", highFloat, high)
			fmt.Fprintf(c.b, "  store float %%%s, ptr %s%s%s\n", lowFloat, alloca, align, metadata)
			fmt.Fprintf(c.b, "  store float %%%s, ptr %s%s%s\n", highFloat, secondAlloca, align, metadata)
			c.markFPResultWritten(off)
			c.markFPResultWritten(off + 4)
			return nil
		}
		// Cast integer sizes when needed (common: i64 reg -> i32 return slot).
		switch {
		case ty == I64 && slotTy == I32:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v)
			fmt.Fprintf(c.b, "  store i32 %%%s, ptr %s%s%s\n", t, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		case ty == I64 && slotTy == LLVMType("double"):
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, v)
			fmt.Fprintf(c.b, "  store double %%%s, ptr %s%s%s\n", t, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		case ty == LLVMType("double") && slotTy == I64:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", t, v)
			fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s%s%s\n", t, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		case ty == I64 && slotTy == Ptr:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v)
			fmt.Fprintf(c.b, "  store ptr %%%s, ptr %s%s%s\n", t, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		case ty == Ptr && slotTy == I64:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, v)
			fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s%s%s\n", t, alloca, align, metadata)
			c.markFPResultWritten(off)
			return nil
		case ty == I64 && slotTy == I64:
			// ok
		default:
			return fmt.Errorf("FP write type mismatch: have %s want %s at +%d(FP)", ty, slotTy, off)
		}
	}
	fmt.Fprintf(c.b, "  store %s %s, ptr %s%s%s\n", ty, v, alloca, align, metadata)
	c.markFPResultWritten(off)
	return nil
}

func (c *amd64Ctx) namedFPResultOffset(name string, fallback int64) int64 {
	if name == "" {
		return fallback
	}
	match := int64(0)
	found := false
	for _, slot := range c.fpResults {
		if slot.Name != name {
			continue
		}
		if found {
			// Aggregate results can have multiple physical FP slots with one Go
			// name. Their explicit offsets remain authoritative.
			return fallback
		}
		match = slot.Offset
		found = true
	}
	if found {
		return match
	}
	return fallback
}

func isSplit64FrameType(typ LLVMType) bool {
	return typ == I64 || typ == LLVMType("double")
}

func (c *amd64Ctx) loadFPResult(slot FrameSlot) (string, error) {
	alloca, ok := c.fpResAllocaIdx[slot.Index]
	if !ok {
		return "", fmt.Errorf("missing fp result alloca for index %d", slot.Index)
	}
	t := c.newTmp()
	align := ""
	if c.classicFrame != "" {
		align = ", align 1"
	}
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s%s\n", t, slot.Type, alloca, align)
	return "%" + t, nil
}

func isAMD64FloatRetTy(ty LLVMType) bool {
	return ty == LLVMType("float") || ty == LLVMType("double")
}

func (c *amd64Ctx) retIntRegByOrd(i int) (Reg, bool) {
	// Go internal ABI integer return registers on amd64.
	retRegs := []Reg{AX, BX, CX, DI, SI, Reg("R8"), Reg("R9"), Reg("R10"), Reg("R11")}
	if i < 0 || i >= len(retRegs) {
		return "", false
	}
	return retRegs[i], true
}

func (c *amd64Ctx) loadRetIntRegTyped(ord int, ty LLVMType) (string, error) {
	r, ok := c.retIntRegByOrd(ord)
	if !ok {
		return llvmZeroValue(ty), nil
	}
	v, err := c.loadReg(r)
	if err != nil {
		return "", err
	}
	switch ty {
	case I64:
		return v, nil
	case I32:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v)
		return "%" + t, nil
	case I16:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, v)
		return "%" + t, nil
	case I8:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, v)
		return "%" + t, nil
	case I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", t, v)
		return "%" + t, nil
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v)
		return "%" + t, nil
	case LLVMType("double"):
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", t, v)
		return "%" + t, nil
	case LLVMType("float"):
		t32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t32, v)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", t, t32)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("unsupported return cast to %s", ty)
	}
}

func (c *amd64Ctx) loadRetFloatRegTyped(ord int, ty LLVMType) (string, error) {
	if ord < 0 || ord > 31 {
		return llvmZeroValue(ty), nil
	}
	xv, err := c.loadX(Reg(fmt.Sprintf("X%d", ord)))
	if err != nil {
		return "", err
	}
	switch ty {
	case LLVMType("double"):
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", bc, xv)
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", lo, bc)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to double\n", t, lo)
		return "%" + t, nil
	case LLVMType("float"):
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", bc, xv)
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %%%s, i32 0\n", lo, bc)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", t, lo)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("unsupported float return type %s", ty)
	}
}

func (c *amd64Ctx) retClassOrdinal(slot FrameSlot) (isFloat bool, ord int) {
	isFloat = isAMD64FloatRetTy(slot.Type)
	ord = 0
	for _, r := range c.fpResults {
		if r.Index == slot.Index {
			return isFloat, ord
		}
		if isAMD64FloatRetTy(r.Type) == isFloat {
			ord++
		}
	}
	return isFloat, ord
}

func (c *amd64Ctx) loadRetSlotFallback(slot FrameSlot) (string, error) {
	isFloat, ord := c.retClassOrdinal(slot)
	if isFloat {
		return c.loadRetFloatRegTyped(ord, slot.Type)
	}
	return c.loadRetIntRegTyped(ord, slot.Type)
}

func parseSBRef(sym string) (base string, off int64, ok bool) {
	// Examples:
	//   r2r1<>+0(SB)
	//   runtime·memequal(SB)
	sym = strings.TrimSpace(sym)
	if strings.HasSuffix(sym, "(SB)") {
		s := strings.TrimSpace(strings.TrimSuffix(sym, "(SB)"))
		if s == "" {
			return "", 0, false
		}
		base, off = splitSymPlusOff(s)
		return base, off, true
	}
	// Also accept bare symbol names used by a few platform asm stubs
	// (e.g. windows arm64 shared-user-data aliases).
	if strings.IndexAny(sym, " \t,") >= 0 {
		return "", 0, false
	}
	if _, ok := parseMem(sym); ok {
		return "", 0, false
	}
	base, off = splitSymPlusOff(sym)
	if strings.TrimSpace(base) == "" {
		return "", 0, false
	}
	return base, off, true
}

func (c *amd64Ctx) addrFromMem(mem MemRef) (addrI64 string, err error) {
	if mem.Segment != "" {
		return "", fmt.Errorf("segment-relative memory requires a segment-aware pointer")
	}
	return c.addrFromPlainMem(mem)
}

func (c *amd64Ctx) addrFromPlainMem(mem MemRef) (addrI64 string, err error) {
	var cur string
	if mem.Sym != "" {
		base, err := c.ptrFromSB(mem.Sym)
		if err != nil {
			return "", err
		}
		addr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", addr, base)
		cur = "%" + addr
	} else {
		base, err := c.loadReg(mem.Base)
		if err != nil {
			return "", err
		}
		cur = base
	}
	if mem.Index != "" {
		idx, err := c.loadReg(mem.Index)
		if err != nil {
			return "", err
		}
		if mem.Scale == 0 {
			mem.Scale = 1
		}
		mul := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %d\n", mul, idx, mem.Scale)
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", add, cur, mul)
		cur = "%" + add
	}
	if mem.Off != 0 {
		add := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", add, cur, mem.Off)
		cur = "%" + add
	}
	return cur, nil
}

func (c *amd64Ctx) ptrFromMem(mem MemRef) (ptr, ptrType string, err error) {
	addr, err := c.addrFromPlainMem(mem)
	if err != nil {
		return "", "", err
	}
	if mem.Segment == "" {
		return c.ptrFromAddrI64(addr), "ptr", nil
	}
	addressSpace := 0
	switch mem.Segment {
	case GS:
		// LLVM's x86 target maps address space 256 to the GS segment.
		addressSpace = 256
	case FS:
		// LLVM's x86 target maps address space 257 to the FS segment.
		addressSpace = 257
	default:
		return "", "", fmt.Errorf("unsupported x86 segment register %s", mem.Segment)
	}
	t := c.newTmp()
	ptrType = fmt.Sprintf("ptr addrspace(%d)", addressSpace)
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to %s\n", t, addr, ptrType)
	return "%" + t, ptrType, nil
}

func (c *amd64Ctx) ptrFromAddrI64(addrI64 string) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, addrI64)
	return "%" + t
}

func (c *amd64Ctx) ptrFromSB(sym string) (ptr string, err error) {
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
	if continuation, ok := c.continuations[res]; ok {
		if off != 0 {
			return "", fmt.Errorf("continuation address cannot have a byte offset: %q", sym)
		}
		return fmt.Sprintf("blockaddress(%s, %%%s)", llvmGlobal(continuation.root), amd64LLVMBlockName(continuation.label)), nil
	}
	if off == 0 {
		return p, nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", t, p, off)
	return "%" + t, nil
}
