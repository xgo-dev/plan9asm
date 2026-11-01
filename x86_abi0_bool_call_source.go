package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

// This request-local plan observes complete logical source and declarations.
// It is not a native CALL, tail, frame backing or caller-memory certificate.
type x86ABI0BoolCallSource struct {
	origin          *File
	original        *File
	signatures      map[string]FuncSig
	resolved        map[string]string
	options         Options
	callers         map[string]*x86ABI0BoolCallPlan
	budget          x86ResultFlowBudget
	tailProofs      map[string]bool
	customGraph     *x86DirectTailGraph
	customSelection *File
	customOptions   Options
}

type x86ABI0BoolCallPlan struct {
	source           *x86ABI0BoolCallSource
	function         Func
	signature        FuncSig
	emittedSignature *FuncSig        // Only the independently emitted nontransport Attrs projection.
	calls            map[int]FuncSig // Original instruction ordinals, never helper/root rewrites.
	bytes            map[int64]bool  // Actual declared outgoing bytes only; padding is absent.
	tail             *x86ABI0BoolTail
	registerTail     *x86CustomHelperBoolTail
}

func x86ABI0BoolCallContext(reason string) error {
	return fmt.Errorf("%w: logical ABI0 bool CALL: %s", ErrProbeNeedsContext, reason)
}

func x86ABI0BoolCallsNeeded(file *File, arch string) bool {
	if file == nil || file.Arch != ArchAMD64 || arch != "386" && arch != "amd64" && arch != "" {
		return false
	}
	for _, fn := range file.Funcs {
		if x86ABI0BoolFunctionControlNeeded(fn) {
			return true
		}
	}
	return false
}

func x86ABI0BoolFunctionControlNeeded(fn Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == "CALL" || ins.Op == OpJMP && len(ins.Args) == 1 && ins.Args[0].Kind == OpSym {
			return true
		}
	}
	return false
}

func x86ABI0BoolCallResolve(options Options, symbol string) string {
	if options.ResolveSym != nil {
		return options.ResolveSym(symbol)
	}
	return symbol
}

// A declared logical no-argument void call transports no caller FP bytes and
// supplies no result knowledge. Its unknown machine effects are revoked even
// when the actual function happens not to return (for example a Go panic).
func x86ABI0NoArgumentVoidCallRole(signature FuncSig) bool {
	return signature.Ret == Void && len(signature.Args) == 0 && len(signature.ArgRegs) == 0 &&
		len(signature.Frame.Params) == 0 && len(signature.Frame.Results) == 0 &&
		signature.ARMEntry == nil && signature.ARM64GoRegisterABI == nil && signature.ARM64ClosureABI == nil &&
		signature.WASMContext == "" && !signature.WASMNative
}

func prepareX86ABI0BoolCalls(file *File, options Options) (*x86ABI0BoolCallSource, error) {
	if !x86ABI0BoolCallsNeeded(file, options.Goarch) {
		return nil, nil
	}
	if options.Goarch == "" {
		options.Goarch = "amd64"
	}
	arch := options.Goarch
	word := x86ResultPointerWord(arch)
	signatures, err := numericalCloneSignatures(options.Sigs)
	if err != nil {
		return nil, err
	}
	source := &x86ABI0BoolCallSource{origin: file, original: x86DirectTailSnapshot(file), options: options,
		signatures: signatures, resolved: make(map[string]string), callers: make(map[string]*x86ABI0BoolCallPlan), tailProofs: make(map[string]bool)}
	needed := false
	for _, fn := range source.original.Funcs {
		if !x86ABI0BoolFunctionControlNeeded(fn) {
			continue
		}
		name := x86ABI0BoolCallResolve(options, fn.Sym)
		source.resolved[fn.Sym] = name
		if sig, declared := signatures[name]; declared && x86ABI0BoolResultNeedsProof(sig, arch) && !fixedLocalPrivateLeafCaller(fn, sig) {
			needed = true
		}
	}
	if !needed {
		// This callback-bearing type query grants nothing. In particular, a
		// changed original source/declaration cannot hide a former candidate.
		if err := source.verify(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if len(file.Funcs) > 256 {
		return nil, x86ABI0BoolCallContext("complete TEXT inventory exceeds its bound")
	}
	byName := make(map[string]Func)
	resolved := make(map[string]bool)
	for _, fn := range source.original.Funcs {
		name, queried := source.resolved[fn.Sym]
		if !queried {
			name = x86ABI0BoolCallResolve(options, fn.Sym)
		}
		if _, duplicate := byName[fn.Sym]; duplicate || name == "" || resolved[name] {
			return nil, x86ABI0BoolCallContext("duplicate or aliased original TEXT identity")
		}
		byName[fn.Sym], source.resolved[fn.Sym], resolved[name] = fn, name, true
	}
	checked := make(map[string]bool)
	for _, fn := range source.original.Funcs {
		if !x86ABI0BoolFunctionControlNeeded(fn) {
			continue
		}
		sig, present := signatures[source.resolved[fn.Sym]]
		if !present || !x86ABI0BoolResultNeedsProof(sig, arch) || fixedLocalPrivateLeafCaller(fn, sig) {
			continue
		}
		if sig.Name != "" && sig.Name != source.resolved[fn.Sym] {
			return nil, x86ABI0BoolCallContext("caller declaration symbol differs from its actual TEXT")
		}
		if arch == "amd64" && !x86ABI0BoolHasCall(fn) && x86DirectTailRootNeeded(fn) {
			// The ordinary direct-tail consumer owns this complete graph and
			// its canonical register result. A private tail is not a 386-only
			// custom helper call and grants no ABI0 bool-frame permission.
			continue
		}
		if !x86ScalarFloatIntegerNativeTarget(arch, options.TargetTriple) {
			return nil, x86ABI0BoolCallContext("logical target does not have the actual x86 word width")
		}
		plan := &x86ABI0BoolCallPlan{source: source, function: fn, signature: sig, calls: make(map[int]FuncSig), bytes: make(map[int64]bool)}
		plan.signature.Name = source.resolved[fn.Sym]
		if !x86ABI0BoolHasCall(fn) {
			if x86DirectTailRootNeeded(fn) {
				if err := source.prepareCustomRegisterTail(plan); err != nil {
					return nil, err
				}
				source.callers[fn.Sym] = plan
				continue
			}
			tail, err := source.prepareTail(fn, sig, byName, make(map[string]bool))
			if err != nil {
				return nil, err
			}
			plan.tail = tail
			if err := plan.replay(); err != nil {
				return nil, err
			}
			source.callers[fn.Sym] = plan
			continue
		}
		for ordinal, ins := range fn.Instrs {
			if ins.Op != "CALL" {
				continue
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				return nil, x86ABI0BoolCallContext("call target is not an exact ordinary SB function")
			}
			name, offset, valid := parseSBRef(ins.Args[0].Sym)
			callee, exists := byName[name]
			if _, queried := source.resolved[name]; !queried && valid && offset == 0 && !strings.Contains(name, "<") {
				source.resolved[name] = x86ABI0BoolCallResolve(options, name)
			}
			calleeSig, declared := signatures[source.resolved[name]]
			if valid && offset == 0 && !strings.Contains(name, "<") && declared &&
				(calleeSig.Name == "" || calleeSig.Name == source.resolved[name]) && x86ABI0NoArgumentVoidCallRole(calleeSig) {
				plan.calls[ordinal] = calleeSig
				continue // No readonly bool leaf, outgoing bytes or result fact.
			}
			if !valid || offset != 0 || !exists || !declared || strings.Contains(name, "<") ||
				calleeSig.Name != "" && calleeSig.Name != source.resolved[name] ||
				!x86ABI0LogicalBoolFrameRole(callee, calleeSig, arch) || len(calleeSig.Args) != 1 || calleeSig.Args[0] != I1 ||
				len(calleeSig.Frame.Params) != 1 || calleeSig.Frame.Params[0].Type != I1 || calleeSig.Frame.Params[0].Offset != 0 ||
				calleeSig.Frame.Params[0].Field != -1 || len(calleeSig.Frame.Params[0].Fields) != 0 ||
				calleeSig.Frame.Results[0].Offset != word || callee.ArgSize != word+1 {
				return nil, x86ABI0BoolCallContext("callee source, ABI or actual bool-byte declaration is not closed")
			}
			if !checked[name] {
				if err := (&x86ABI0BoolCallPlan{function: callee}).replay(); err != nil {
					return nil, err
				}
				for _, effect := range callee.Instrs {
					if effect.Op == "CALL" || effect.Op == OpJMP && len(effect.Args) == 1 && effect.Args[0].Kind == OpSym {
						return nil, x86ABI0BoolCallContext("leaf has an unknown call or external tail effect")
					}
				}
				leaf := callee
				leaf.x86ResultFlowBudget = &source.budget
				leaf.x86BoolReadonlyInputs = true
				if err := checkX86ABI0ResultInitializationAtSource(leaf, calleeSig, arch, func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
					return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
				}, true); err != nil {
					return nil, err
				}
				checked[name] = true
			}
			plan.calls[ordinal] = calleeSig
			plan.bytes[0], plan.bytes[word] = true, true
		}
		if len(plan.calls) == 0 {
			continue
		}
		role := fn
		role.FrameSize = 0
		if fn.FrameSize < 0 || len(plan.bytes) != 0 && fn.FrameSize < word+1 || fn.FrameSize > 4096 ||
			!x86ABI0LogicalBoolFrameRole(role, sig, arch) || fn.x86DirectTailRoot != nil {
			return nil, x86ABI0BoolCallContext("caller lacks its complete bounded ordinary logical frame")
		}
		if err := plan.replay(); err != nil {
			return nil, err
		}
		source.callers[fn.Sym] = plan
	}
	if err := source.verify(); err != nil {
		return nil, err
	}
	if len(source.callers) == 0 {
		return nil, nil
	}
	if source.customGraph != nil {
		// Match the continuation producer's complete-file audit before any
		// selection. The already sealed plan prevents recursive preparation.
		request := options
		request.x86BoolCallSource = source
		if _, err := translateIRText(file, request); err != nil {
			source.customGraph.revoked.Store(true)
			return nil, err
		}
	}
	return source, nil
}

func (source *x86ABI0BoolCallSource) verify() (result error) {
	defer func() {
		if result != nil && source.customGraph != nil {
			source.customGraph.revoked.Store(true)
		}
	}()
	// Resolve callbacks finish before the final source/declaration snapshot.
	for original, name := range source.resolved {
		if x86ABI0BoolCallResolve(source.options, original) != name {
			return x86ABI0BoolCallContext("TEXT resolution changed")
		}
	}
	if !reflect.DeepEqual(source.original, x86DirectTailSnapshot(source.origin)) || !reflect.DeepEqual(source.signatures, source.options.Sigs) {
		return x86ABI0BoolCallContext("complete original source or declarations changed")
	}
	if source.customGraph != nil {
		if err := source.customGraph.verify(source.origin, source.options); err != nil {
			return err
		}
		if source.customSelection != nil {
			owned, err := source.ownsCustomRegisterTails(source.customSelection, source.customOptions)
			if err != nil {
				return err
			}
			if !owned {
				return x86ABI0BoolCallContext("selected custom helper closure changed")
			}
		}
	}
	return nil
}

func (plan *x86ABI0BoolCallPlan) replay() error {
	var literal strings.Builder
	for _, ins := range plan.function.Instrs {
		if ins.Raw == "" || len(ins.Raw) > (1<<20)-literal.Len()-1 {
			return x86ABI0BoolCallContext("missing or oversized original caller literal")
		}
		literal.WriteString(ins.Raw)
		literal.WriteByte('\n')
	}
	parsed, err := Parse(ArchAMD64, literal.String())
	if err != nil || len(parsed.Funcs) != 1 || len(parsed.Data) != 0 || len(parsed.Globl) != 0 || len(parsed.UnlinkedPrelude) != 0 ||
		!reflect.DeepEqual(parsed.Funcs[0], plan.function) {
		return x86ABI0BoolCallContext("caller original TEXT/operand tuple cannot be replayed")
	}
	return nil
}

func (plan *x86ABI0BoolCallPlan) matches(fn Func, sig FuncSig, arch string) bool {
	fn.x86BoolCalls = nil
	fn.x86ResultFlowBudget = nil
	if sig.Name == "" {
		sig.Name = plan.source.resolved[fn.Sym]
	}
	return arch == plan.source.options.Goarch && reflect.DeepEqual(fn, plan.function) &&
		(reflect.DeepEqual(sig, plan.signature) || plan.emittedSignature != nil && reflect.DeepEqual(sig, *plan.emittedSignature))
}

func (plan *x86ABI0BoolCallPlan) bindLowering(fn Func, declaration, emitted FuncSig, arch string) bool {
	// The lowerer already saved this actual declaration before inferring its
	// target-feature attribute group. Only that one nontransport field may be
	// projected; name, ABI, slots, native fields and all other fields stay exact.
	if !plan.matches(fn, declaration, arch) {
		return false
	}
	projected := plan.signature
	projected.Attrs = emitted.Attrs
	if !reflect.DeepEqual(projected, emitted) {
		return false
	}
	plan.emittedSignature = &projected
	return true
}

func x86ABI0BoolOutgoingOffset(arg Operand, plan *x86ABI0BoolCallPlan) (int, bool) {
	if plan == nil || arg.Kind != OpMem || arg.Mem.Base != SP || !x86ResultSlotMemory(arg.Mem) || !plan.bytes[arg.Mem.Off] {
		return 0, false
	}
	return int(arg.Mem.Off), true
}
