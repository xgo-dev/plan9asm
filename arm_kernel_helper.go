package plan9asm

import (
	"fmt"
	"strings"
)

type armKernelEntry uint8

const (
	armKernelCompareExchange32 armKernelEntry = iota + 1
	armKernelMemoryBarrier
)

type armKernelSpec struct {
	entry  armKernelEntry
	addr   uint32
	inputs []Reg
}

// These are Linux's documented user-mode entry points, not function-name
// aliases. The native cmpxchg ABI returns status in R0 and success in C, and
// clobbers R3/IP/flags. The barrier preserves registers and orders memory.
// https://docs.kernel.org/arch/arm/kernel_user_helpers.html
var armKernelSpecs = [...]armKernelSpec{
	{entry: armKernelCompareExchange32, addr: 0xffff0fc0, inputs: []Reg{"R0", "R1", "R2"}},
	{entry: armKernelMemoryBarrier, addr: 0xffff0fa0},
}

type armKernelCall struct {
	spec      armKernelSpec
	condition string
	tail      bool
}

func armKernelBranchForm(ins Instr) (condition string, tail bool, ok bool) {
	op, condition, _, _ := armDecodeOp(string(ins.Op))
	if op == "BL" || op == "CALL" || op == "B" || op == "JMP" {
		if err := armRequireConditionOnlySuffix(ins); err != nil {
			return "", false, false
		}
		return condition, op == "B" || op == "JMP", true
	}
	if len(op) > 1 && op[0] == 'B' && armCondCodes[op[1:]] {
		return op[1:], true, true
	}
	return "", false, false
}

func armKernelSourceSpec(fn Func) (armKernelSpec, bool) {
	if !strings.HasSuffix(fn.Sym, "<>") || fn.FrameSize != 0 || fn.ArgSize != 0 || len(fn.Instrs) != 2 || fn.Instrs[0].Op != OpTEXT {
		return armKernelSpec{}, false
	}
	ins := fn.Instrs[1]
	if ins.Op != "MOVW" || len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[1].Kind != OpReg || ins.Args[1].Reg != "R15" {
		return armKernelSpec{}, false
	}
	for _, spec := range armKernelSpecs {
		if ins.Args[0].Imm == int64(spec.addr) || ins.Args[0].Imm == int64(int32(spec.addr)) {
			return spec, true
		}
	}
	return armKernelSpec{}, false
}

// ARMKernelHelperFuncSig identifies a source-local Linux kernel entry thunk.
// It is a metadata placeholder, not a void C ABI callable: translation must
// still prove the concrete Linux target and every closed native continuation.
// No name heuristic, public symbol, extra instruction, or FP frame is accepted.
func ARMKernelHelperFuncSig(fn Func, resolved string) (FuncSig, bool) {
	if _, ok := armKernelSourceSpec(fn); !ok {
		return FuncSig{}, false
	}
	return FuncSig{Name: resolved, Ret: Void}, true
}

func prepareARMKernelHelpers(file *File, opt Options) (*File, error) {
	if file.Arch != ArchARM {
		return file, nil
	}
	helpers := map[string]armKernelSpec{}
	seen := map[string]bool{}
	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(s string) string { return s }
	}
	for _, fn := range file.Funcs {
		if seen[fn.Sym] {
			return nil, fmt.Errorf("duplicate ARM TEXT %q", fn.Sym)
		}
		seen[fn.Sym] = true
		spec, ok := armKernelSourceSpec(fn)
		if !ok {
			continue
		}
		if !strings.Contains(opt.TargetTriple, "-linux-") {
			return nil, fmt.Errorf("%w: ARM kernel helper %q requires a concrete Linux target", ErrProbeNeedsContext, fn.Sym)
		}
		sig, ok := opt.Sigs[resolve(fn.Sym)]
		if !ok || sig.Name != "" && sig.Name != resolve(fn.Sym) || sig.Ret != Void || len(sig.Args) != 0 || len(sig.ArgRegs) != 0 || len(sig.Frame.Params)+len(sig.Frame.Results) != 0 {
			return nil, fmt.Errorf("%w: ARM kernel helper %q needs a private native register ABI, not a Go/FP entry", ErrProbeNeedsContext, fn.Sym)
		}
		if _, duplicate := helpers[fn.Sym]; duplicate {
			return nil, fmt.Errorf("duplicate ARM kernel helper %q", fn.Sym)
		}
		helpers[fn.Sym] = spec
	}
	if len(helpers) == 0 {
		return file, nil
	}

	uses := map[string]int{}
	result := *file
	result.Funcs = make([]Func, 0, len(file.Funcs))
	for _, fn := range file.Funcs {
		if _, helper := helpers[fn.Sym]; helper {
			continue
		}
		copyFn := fn
		copyFn.Instrs = append([]Instr(nil), fn.Instrs...)
		for i, ins := range copyFn.Instrs {
			for ai, arg := range ins.Args {
				if arg.Kind != OpSym {
					continue
				}
				base, off, ok := parseSBRef(arg.Sym)
				spec, helper := helpers[strings.TrimPrefix(base, "$")]
				if !ok || !helper {
					continue
				}
				condition, tail, branch := armKernelBranchForm(ins)
				if branch && tail && condition != "" && condition != "AL" {
					return nil, fmt.Errorf("arm conditional branch to a symbolic helper is absent from Go's assembler grammar: %s", ins.Raw)
				}
				if !branch || off != 0 || ai != 0 || len(ins.Args) != 1 || strings.HasPrefix(base, "$") {
					return nil, fmt.Errorf("%w: ARM kernel helper address escapes its direct continuation in %q: %s", ErrProbeNeedsContext, fn.Sym, ins.Raw)
				}
				copyFn.Instrs[i].armKernelCall = &armKernelCall{spec: spec, condition: condition, tail: tail}
				uses[base]++
			}
		}
		if err := proveARMKernelContinuation(copyFn); err != nil {
			return nil, err
		}
		if err := proveARMKernelInputs(copyFn, opt.Sigs[resolve(fn.Sym)]); err != nil {
			return nil, err
		}
		result.Funcs = append(result.Funcs, copyFn)
	}
	for _, data := range file.Data {
		if _, helper := helpers[data.Sym]; helper {
			return nil, fmt.Errorf("%w: ARM kernel helper cannot contain DATA", ErrProbeNeedsContext)
		}
		base, _, _ := parseSBRef(data.Addr)
		if _, helper := helpers[strings.TrimPrefix(base, "$")]; helper {
			return nil, fmt.Errorf("%w: ARM kernel helper address escapes through DATA", ErrProbeNeedsContext)
		}
	}
	for _, global := range file.Globl {
		if _, helper := helpers[global.Sym]; helper {
			return nil, fmt.Errorf("%w: ARM kernel helper cannot be a data global", ErrProbeNeedsContext)
		}
	}
	for name := range helpers {
		if uses[name] == 0 {
			return nil, fmt.Errorf("%w: ARM kernel helper %q has no closed caller continuation", ErrProbeNeedsContext, name)
		}
	}
	return &result, nil
}

func armKernelValueDefined(source Operand, sig FuncSig, defined armKernelState) bool {
	switch source.Kind {
	case OpImm:
		return source.ImmRaw == ""
	case OpReg:
		return defined.has(armKernelRegBit(source.Reg))
	case OpFP, OpFPAddr:
		return armKernelTypedFPInput(source, sig)
	case OpRegShift:
		return defined.has(armKernelRegBit(source.Reg)) && (source.ShiftReg == "" || defined.has(armKernelRegBit(source.ShiftReg)))
	case OpMem:
		return defined.has(armKernelRegBit(source.Mem.Base)) && (source.Mem.Index == "" || defined.has(armKernelRegBit(source.Mem.Index))) && source.Mem.OffRaw == ""
	case OpSym:
		_, _, ok := parseSBRef(source.Sym)
		return ok && strings.HasSuffix(source.Sym, "(SB)")
	}
	return false
}

func armKernelTypedFPInput(source Operand, sig FuncSig) bool {
	for _, slot := range sig.Frame.Params {
		if slot.Offset == source.FPOffset && slot.Index >= 0 && slot.Index < len(sig.Args) {
			return true
		}
	}
	return false
}

func (c *armCtx) lowerKernelHelperCall(call armKernelCall) (bool, error) {
	emit := func() error {
		if err := c.emitKernelHelper(call.spec); err != nil {
			return err
		}
		if call.tail {
			return c.lowerRET()
		}
		return nil
	}
	if call.condition == "" || call.condition == "AL" {
		return call.tail, emit()
	}
	return false, c.emitConditionalEffect(call.condition, emit)
}

func (c *armCtx) emitKernelHelper(spec armKernelSpec) error {
	if spec.entry == armKernelMemoryBarrier {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %d)\n", "blx $0", "r,~{lr},~{memory}", spec.addr)
		return nil
	}
	inputs := make([]string, len(spec.inputs))
	for i, reg := range spec.inputs {
		value, err := c.loadReg(reg)
		if err != nil {
			return err
		}
		inputs[i] = value
	}
	result := c.newTmp()
	// Read status and APSR inside the same assembly region as the call: an
	// ordinary LLVM function return does not carry the callee's flags. R3/IP
	// are explicit outputs as well, preserving any subsequent source reads.
	fmt.Fprintf(c.b, "  %%%s = call {i32,i32,i32,i32} asm sideeffect %q, %q(i32 %s, i32 %s, i32 %s, i32 %d)\n",
		result, "blx $7; mrs $3, apsr", "={r0},={r3},={r12},=&r,0,{r1},{r2},r,~{lr},~{cc},~{memory}",
		inputs[0], inputs[1], inputs[2], spec.addr)
	for i, reg := range []Reg{"R0", "R3", "R12"} {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue {i32,i32,i32,i32} %%%s, %d\n", value, result, i)
		if err := c.storeReg(reg, "%"+value); err != nil {
			return err
		}
	}
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue {i32,i32,i32,i32} %%%s, 3\n", status, result)
	c.storeFlagsFromStatus("%" + status)
	return nil
}
