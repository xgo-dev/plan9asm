package plan9asm

import (
	"reflect"
	"strings"
)

// A terminal forwards only existing logical arguments and an independently
// declared canonical I1 result. It creates no FP writes, GP/FLAGS state,
// memory origin, physical frame, native entry or C _Bool transport permission.
type x86ABI0BoolTail struct {
	target    string
	signature FuncSig
}

func x86ABI0BoolHasCall(fn Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == "CALL" {
			return true
		}
	}
	return false
}

func x86ABI0BoolTailTarget(fn Func) (string, bool) {
	if fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") || len(fn.X86RawText) != 0 ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil ||
		len(fn.Instrs) != 2 || fn.Instrs[0].Op != OpTEXT {
		return "", false
	}
	for _, ins := range fn.Instrs {
		if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
			ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return "", false
		}
	}
	ins := fn.Instrs[1]
	if ins.Op != OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
		return "", false
	}
	name, offset, valid := parseSBRef(ins.Args[0].Sym)
	return name, valid && offset == 0 && !strings.Contains(name, "<")
}

func x86ABI0BoolTailTransport(left, right FuncSig, arch string) bool {
	if !x86ABI0BoolDeclarationRole(left, arch) || !x86ABI0BoolDeclarationRole(right, arch) {
		return false
	}
	// Source variable/result names are descriptive, not transport. All actual
	// offsets, types, field paths, argument order and ABI/native fields remain.
	project := func(sig FuncSig) FuncSig {
		sig.Name, sig.Attrs = "", ""
		sig.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
		sig.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
		for index := range sig.Frame.Params {
			sig.Frame.Params[index].Name = ""
		}
		for index := range sig.Frame.Results {
			sig.Frame.Results[index].Name = ""
		}
		return sig
	}
	return reflect.DeepEqual(project(left), project(right))
}

func (source *x86ABI0BoolCallSource) prepareTail(fn Func, sig FuncSig, byName map[string]Func, visiting map[string]bool) (*x86ABI0BoolTail, error) {
	arch := source.options.Goarch
	name, valid := x86ABI0BoolTailTarget(fn)
	if !valid || !x86ABI0BoolDeclarationRole(sig, arch) ||
		fn.ArgSize != 0 && fn.ArgSize != sig.Frame.Results[0].Offset+1 {
		return nil, x86ABI0BoolCallContext("tail lacks an exact zero-frame ordinary canonical terminal")
	}
	if _, queried := source.resolved[name]; !queried {
		source.resolved[name] = x86ABI0BoolCallResolve(source.options, name)
	}
	calleeName := source.resolved[name]
	calleeSig, declared := source.signatures[calleeName]
	if calleeName == "" || !declared || calleeSig.Name != "" && calleeSig.Name != calleeName ||
		!x86ABI0BoolTailTransport(sig, calleeSig, arch) {
		return nil, x86ABI0BoolCallContext("tail target lacks its independent exact canonical declaration/transport")
	}
	if callee, exists := byName[name]; exists && !source.tailProofs[name] {
		if visiting[name] || len(visiting) >= 256 {
			return nil, x86ABI0BoolCallContext("same-file canonical terminal has a cycle or exceeds the complete source bound")
		}
		visiting[name] = true
		defer delete(visiting, name)
		if x86ABI0BoolFunctionControlNeeded(callee) {
			if x86ABI0BoolHasCall(callee) {
				return nil, x86ABI0BoolCallContext("tail callee needs its independent CALL contract")
			}
			if _, err := source.prepareTail(callee, calleeSig, byName, visiting); err != nil {
				return nil, err
			}
		} else {
			if err := (&x86ABI0BoolCallPlan{function: callee}).replay(); err != nil {
				return nil, err
			}
			callee.x86ResultFlowBudget = &source.budget
			resolve := func(symbol string) string { return x86ABI0BoolCallResolve(source.options, symbol) }
			consumer := newX86Ctx(new(strings.Builder), callee, calleeSig, resolve, source.signatures, arch, source.options.TargetTriple, false)
			consumer.fpScalarData = x86LoweredScalarDataReads(source.original, resolve, source.signatures, arch)
			consumer.fpShiftLiterals = x86LoweredShiftLiterals(source.original, resolve,
				x86LoweredStaticAddressValues(source.original, resolve, source.signatures, arch), arch)
			consumer.goReadOnlyStorage = source.options.goReadOnlyStorage
			if err := consumer.checkLoweredScalarFPResultInitialization(); err != nil {
				return nil, err
			}
		}
		source.tailProofs[name] = true // Same cached source/byte/visit budget, never reset.
	}
	return &x86ABI0BoolTail{target: calleeName, signature: calleeSig}, nil
}

func (plan *x86ABI0BoolCallPlan) checkTailTerminal(fn Func, sig FuncSig, arch string) error {
	if plan.tail == nil || !plan.matches(fn, sig, arch) || !x86ABI0BoolTailTransport(plan.signature, plan.tail.signature, arch) ||
		!reflect.DeepEqual(plan.source.signatures[plan.tail.target], plan.tail.signature) {
		return x86ABI0BoolCallContext("tail consumption changed its original source or exact declaration")
	}
	return plan.source.verify() // All callbacks precede the final complete source/type snapshot.
}
