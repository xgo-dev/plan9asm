package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
)

// A node keeps the original source coordinates. A continuation is neither a
// callable function nor a new entry/closure/frame/register capability.
type x86DirectTailPoint struct {
	text, instruction int
}

type x86DirectTailGraph struct {
	origin          *File
	original        *File
	goarch          string
	revoked         atomic.Bool
	signatures      map[string]FuncSig
	symbols         map[string]string
	externalSymbols map[string]string
	helpers         map[string]bool
	roots           map[string]*x86DirectTailRoot
	texts           map[string]int // Immutable original TEXT lookup; no expanded views.
	numerical       *GoX86NumericalReadBinding
	fixedLocal      *x86FixedLocalBinding
}

type x86DirectTailRoot struct {
	graph         *x86DirectTailGraph
	text          int
	points        []x86DirectTailPoint
	instructions  []Instr
	ordinals      []int
	edges         [][]int
	externalTails []bool // Exact ordinary typed terminals, never helper ABIs.
}

func x86DirectTailContext(format string, args ...any) error {
	return fmt.Errorf("%w: x86 direct-tail source: %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

func x86DirectTailSnapshot(file *File) *File {
	copy := arm64ScratchFileSnapshot(file)
	copy.x86DirectTails = nil
	for i := range copy.Funcs {
		copy.Funcs[i].x86DirectTailRoot = nil
		copy.Funcs[i].x86ResultFlowBudget = nil
		copy.Funcs[i].x86BoolCalls = nil
		copy.Funcs[i].x86BoolReadonlyInputs = false
		for ordinal := range copy.Funcs[i].Instrs {
			copy.Funcs[i].Instrs[ordinal] = x86DirectTailInstructionSnapshot(copy.Funcs[i].Instrs[ordinal])
		}
	}
	return copy
}

// A cost predicate, never a source/entry/state permission. Private source CALL
// and tail edges share this graph; native/raw calls keep their own consumers.
func x86DirectTailSourceNeeded(file *File) bool {
	if file == nil || file.Arch != ArchAMD64 {
		return false
	}
	for _, fn := range file.Funcs {
		if x86DirectTailRootNeeded(fn) {
			return true
		}
	}
	return false
}

func x86DirectTailRootNeeded(fn Func) bool {
	return x86DirectTailRootNeededExceptCalls(fn, nil)
}

func x86DirectTailRootNeededExceptCalls(fn Func, ordinary map[string]bool) bool {
	return x86DirectTailRootTargets(fn, nil, ordinary)
}

func x86DirectTailRootTargets(fn Func, helpers, ordinary map[string]bool) bool {
	for _, ins := range fn.Instrs {
		if ins.Op != OpJMP && ins.Op != OpCALL || len(ins.Args) != 1 {
			continue
		}
		arg := ins.Args[0]
		text := arg.Sym
		if arg.Kind == OpMem {
			text = arg.Mem.Sym
		}
		base, offset, valid := parseSBRef(strings.TrimPrefix(text, "$"))
		if valid && (helpers == nil && strings.HasSuffix(base, "<>") || helpers[base]) {
			if ins.Op == OpCALL && arg.Kind == OpSym && offset == 0 && ordinary[base] {
				continue
			}
			return true
		}
	}
	return false
}

// PrepareX86DirectTailSource audits the complete source before any root filter
// or module partition. Only request-local copies receive its private graph.
// The existing actual root signature supplies its logical state/RET contract;
// a helper signature, zero arguments or matching returns supplies nothing.
// Private CALL additionally requires a closed helper prologue/return context.
// Native raw/stack/closure/entry and numerical-source composition stay separate.
func PrepareX86DirectTailSource(file *File, options Options) (*File, error) {
	if file == nil {
		return file, nil
	}
	if prepared, handled, err := prepareX86FixedLocalLeafSource(file, options); handled {
		return prepared, err
	}
	calls := options.x86BoolCallSource
	if calls == nil {
		var err error
		calls, err = prepareX86ABI0BoolCalls(file, options)
		if err != nil {
			return nil, err
		}
	}
	if calls != nil {
		owned, err := calls.ownsCustomRegisterTails(file, options)
		if err != nil || owned {
			return file, err // Complete canonical graph proof; retain the actual custom calls.
		}
	}
	if file.x86DirectTails != nil {
		if err := file.x86DirectTails.verify(file, options); err != nil {
			return nil, err
		}
		return file, nil
	}
	if file.Arch != ArchAMD64 || len(options.X86TailGroups) != 0 {
		return file, nil
	}
	if !x86DirectTailSourceNeeded(file) {
		return file, nil
	}
	goarch := options.Goarch
	if goarch == "" {
		goarch = "amd64"
	}
	if goarch != "amd64" && goarch != "386" {
		return nil, x86DirectTailContext("source graph has no registered x86 mode")
	}
	helpers := make(map[string]bool)
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") {
			helpers[fn.Sym] = true
		}
	}
	if len(helpers) == 0 {
		return nil, x86DirectTailContext("private tail target has no original source TEXT")
	}
	if options.X86TLSMoves != nil || options.ARM64ByteCarrierSource != nil ||
		len(file.UnlinkedPrelude) != 0 || len(file.x86Continuations) != 0 {
		return nil, x86DirectTailContext("source/native binding needs its independent complete node association")
	}
	request, err := x86DirectTailNumericalRequest(file, options)
	if err != nil {
		return nil, err
	}
	graph, byName, err := newX86DirectTailGraph(file, options, helpers, goarch)
	if err != nil {
		return nil, err
	}
	ordinary := graph.ordinaryABI0Calls()
	for helper := range ordinary {
		delete(helpers, helper)
	}
	signatures, resolve := graph.signatures, options.ResolveSym
	if resolve == nil {
		resolve = func(symbol string) string { return symbol }
	}
	reached := make(map[string]bool)
	combined := 0
	for index, fn := range graph.original.Funcs {
		if helpers[fn.Sym] || !x86DirectTailRootNeededExceptCalls(fn, ordinary) {
			continue
		}
		view, err := graph.root(index, byName, 4096-combined, true)
		if err != nil {
			return nil, err
		}
		if len(view.points) == len(x86DirectTailInstructions(fn)) {
			continue // This entry has no edge into the private helper graph.
		}
		combined += len(view.points)
		if combined > 4096 {
			return nil, x86DirectTailContext("combined source/continuation instruction budget exhausted")
		}
		for _, point := range view.points {
			reached[graph.original.Funcs[point.text].Sym] = true
		}
		graph.roots[fn.Sym] = view
	}
	for helper := range helpers {
		if !reached[helper] {
			return nil, x86DirectTailContext("private helper lacks a closed typed root: %s", helper)
		}
	}
	request.x86DirectTails = graph
	if err := graph.joinNumericalNodes(request); err != nil {
		return nil, err
	}
	budget := &x86ResultFlowBudget{}
	for _, view := range graph.roots {
		fn := graph.original.Funcs[view.text]
		sig, present := signatures[graph.symbols[fn.Sym]]
		if !present || sig.Name != "" && sig.Name != graph.symbols[fn.Sym] {
			return nil, x86DirectTailContext("root lacks its complete typed signature: %s", fn.Sym)
		}
		fn.x86DirectTailRoot = view // Local proof view, never the user's Func.
		fn.x86ResultFlowBudget = budget
		if x86DirectTailSigNeedsOwnBoolFrame(sig, fn, goarch) {
			return nil, x86DirectTailContext("ABI0 bool byte needs its independent canonical frame contract")
		}
		c := newX86Ctx(new(strings.Builder), fn, sig, resolve, signatures, goarch, options.TargetTriple, false)
		c.fpScalarData = x86LoweredScalarDataReads(graph.original, resolve, signatures, goarch)
		c.fpShiftLiterals = x86LoweredShiftLiterals(graph.original, resolve,
			x86LoweredStaticAddressValues(graph.original, resolve, signatures, goarch), goarch)
		c.goReadOnlyStorage = options.goReadOnlyStorage
		if err := c.checkLoweredScalarFPResultInitialization(); err != nil {
			return nil, err
		}
	}
	if err := graph.verify(request, options); err != nil {
		return nil, err
	}
	// Audit ordinary nonparticipants through their registered consumers, not
	// the graph's call-free/zero-frame rule. This is the complete unchanged
	// request, before KeepFunc or partitioning. Existing graph preparation only
	// verifies here, so shared lowering does not recursively build another graph.
	if _, err := translateIRText(request, options); err != nil {
		graph.revoked.Store(true)
		return nil, err
	}
	return request, nil
}

// Routing only: an already declared bounded Void ABI0 callee retains its own
// ordinary lowering checks. No declaration is inferred for register helpers.
// Inspect the captured source/symbols so a resolver cannot change the source
// before the graph's identity checks. Non-CALL references keep the old graph.
func (graph *x86DirectTailGraph) ordinaryABI0Calls() map[string]bool {
	ordinary := make(map[string]bool)
	for _, fn := range graph.original.Funcs {
		name := graph.symbols[fn.Sym]
		sig, found := graph.signatures[name]
		if graph.helpers[fn.Sym] && found && (sig.Name == "" || sig.Name == name) &&
			x86BoundedVoidABI0Declaration(fn, sig, graph.goarch) {
			ordinary[fn.Sym] = true
		}
	}
	for _, fn := range graph.original.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == OpTEXT || ins.Op == OpCALL {
				continue // auditReferences already checked exact CALL operands.
			}
			for _, arg := range ins.Args {
				if name, _, valid := parseSBRef(arg.Sym); valid {
					delete(ordinary, name)
				}
			}
		}
	}
	return ordinary
}

func x86BoundedVoidABI0Declaration(fn Func, sig FuncSig, arch string) bool {
	if arch != "amd64" && arch != "386" || sig.Ret != Void || len(sig.Args) == 0 ||
		len(sig.Frame.Params) == 0 || sig.WASMNative || sig.x86BorrowedBoolTail ||
		fn.ArgSize <= 0 || fn.ArgSize > 4096 || len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT {
		return false
	}
	op, rest := splitOpcode(fn.Instrs[0].Raw)
	frame, err := parseTEXTFrameSpec(strings.Split(rest, ","))
	return strings.EqualFold(op, "TEXT") && err == nil && frame.argsSpecified &&
		frame.frameSize == fn.FrameSize && frame.argSize == fn.ArgSize && x86ABI0FrameLayout(sig, fn.ArgSize, arch)
}

// Both continuation emission and a separately sealed custom-register result
// plan use this same complete original source/reference/signature producer.
func newX86DirectTailGraph(file *File, options Options, helpers map[string]bool, goarch string) (*x86DirectTailGraph, map[string]int, error) {
	resolve := options.ResolveSym
	if resolve == nil {
		resolve = func(symbol string) string { return symbol }
	}
	graph := &x86DirectTailGraph{origin: file, original: x86DirectTailSnapshot(file), goarch: goarch, helpers: helpers,
		symbols: make(map[string]string), externalSymbols: make(map[string]string), roots: make(map[string]*x86DirectTailRoot), numerical: options.NumericalReads}
	signatures, err := numericalCloneSignatures(options.Sigs)
	if err != nil {
		return nil, nil, err
	}
	graph.signatures = signatures
	byName := make(map[string]int)
	graph.texts = byName
	resolved := make(map[string]bool)
	for index, fn := range graph.original.Funcs {
		name := resolve(fn.Sym)
		if _, duplicate := byName[fn.Sym]; duplicate || name == "" || resolved[name] {
			return nil, nil, x86DirectTailContext("missing, duplicate or aliased original TEXT identity")
		}
		byName[fn.Sym], graph.symbols[fn.Sym], resolved[name] = index, name, true
	}
	for _, fn := range graph.original.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == OpJMP && len(ins.Args) == 1 && ins.Args[0].Kind == OpSym {
				if name, offset, valid := parseSBRef(ins.Args[0].Sym); valid && offset == 0 && !helpers[name] {
					graph.externalSymbols[name] = resolve(name)
				}
			}
		}
	}
	if !reflect.DeepEqual(graph.original, x86DirectTailSnapshot(file)) || !reflect.DeepEqual(graph.signatures, options.Sigs) {
		return nil, nil, x86DirectTailContext("resolver changed complete source or signatures")
	}
	if err := graph.auditReferences(); err != nil {
		return nil, nil, err
	}
	return graph, byName, nil
}

func x86DirectTailInstructions(fn Func) []x86DirectTailPoint {
	var points []x86DirectTailPoint
	for ordinal, ins := range fn.Instrs {
		if ins.Op != OpTEXT && ins.Op != OpLABEL {
			points = append(points, x86DirectTailPoint{instruction: ordinal})
		}
	}
	return points
}

func (graph *x86DirectTailGraph) auditReferences() error {
	for _, fn := range graph.original.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == OpTEXT {
				continue
			}
			for _, arg := range ins.Args {
				text := arg.Sym
				if arg.Kind == OpMem {
					text = arg.Mem.Sym
				}
				base, offset, valid := parseSBRef(strings.TrimPrefix(text, "$"))
				if !valid || !graph.helpers[base] {
					continue
				}
				if ins.Op != OpJMP && ins.Op != OpCALL || len(ins.Args) != 1 || arg.Kind != OpSym || offset != 0 || strings.HasPrefix(text, "$") {
					return x86DirectTailContext("helper address/call/offset escape in %s: %s", fn.Sym, ins.Raw)
				}
			}
		}
	}
	for _, data := range graph.original.Data {
		base, _, valid := parseSBRef(strings.TrimPrefix(data.Addr, "$"))
		if graph.helpers[data.Sym] || valid && graph.helpers[base] {
			return x86DirectTailContext("helper address escapes through DATA")
		}
	}
	for _, global := range graph.original.Globl {
		if graph.helpers[global.Sym] {
			return x86DirectTailContext("helper TEXT identity also names GLOBL storage")
		}
	}
	return nil
}

func (graph *x86DirectTailGraph) verify(file *File, options Options) (result error) {
	if graph != nil {
		defer func() {
			if result != nil {
				graph.revoked.Store(true)
			}
		}()
	}
	goarch := options.Goarch
	if goarch == "" {
		goarch = "amd64"
	}
	if graph == nil || graph.origin == nil || graph.original == nil || file == nil ||
		graph.revoked.Load() || graph.goarch != goarch || file.Arch != ArchAMD64 || len(options.X86TailGroups) != 0 ||
		options.NumericalReads != graph.numerical || options.X86TLSMoves != nil || options.ARM64ByteCarrierSource != nil ||
		!reflect.DeepEqual(x86DirectTailSnapshot(graph.origin), graph.original) || !reflect.DeepEqual(graph.signatures, options.Sigs) {
		return x86DirectTailContext("original complete source/signature identity changed")
	}
	if graph.numerical != nil {
		if err := verifyNumericalReadInputs(graph.origin, options); err != nil {
			return err
		}
		if err := verifyNormalizedNumericalReads(file, options); err != nil {
			return err
		}
	}
	before := x86DirectTailSnapshot(file)
	selected := x86DirectTailSnapshot(file)
	selected.Funcs = graph.original.Funcs
	if !reflect.DeepEqual(selected, graph.original) {
		return x86DirectTailContext("selected complete DATA/GLOBL/prelude identity changed")
	}
	seen := make(map[string]bool)
	for _, fn := range file.Funcs {
		if seen[fn.Sym] {
			return x86DirectTailContext("duplicate selected original TEXT")
		}
		seen[fn.Sym] = true
		public := arm64PrivateTailSnapshot(fn)
		if graph.fixedLocal != nil {
			if public.x86FixedLocal != nil && public.x86FixedLocal.binding != graph.fixedLocal ||
				public.x86DirectTailRoot != nil && public.x86DirectTailRoot.graph != graph {
				return x86DirectTailContext("normalized frame belongs to another source graph")
			}
			public.x86FixedLocal, public.x86DirectTailRoot, public.x86RawReplay = nil, nil, nil
		}
		for ordinal := range public.Instrs {
			public.Instrs[ordinal] = x86DirectTailInstructionSnapshot(public.Instrs[ordinal])
		}
		found := false
		for _, original := range graph.original.Funcs {
			if fn.Sym == original.Sym && reflect.DeepEqual(public, original) {
				found = true
			}
		}
		if !found {
			return x86DirectTailContext("selected entry no longer belongs to complete original source")
		}
	}
	resolve := options.ResolveSym
	if resolve == nil {
		resolve = func(symbol string) string { return symbol }
	}
	for _, fn := range graph.original.Funcs {
		if resolve(fn.Sym) != graph.symbols[fn.Sym] {
			return x86DirectTailContext("original source symbol mapping changed")
		}
	}
	for symbol, expected := range graph.externalSymbols {
		if resolve(symbol) != expected {
			return x86DirectTailContext("external typed terminal symbol mapping changed")
		}
	}
	if graph.revoked.Load() || !reflect.DeepEqual(x86DirectTailSnapshot(graph.origin), graph.original) || !reflect.DeepEqual(graph.signatures, options.Sigs) ||
		!reflect.DeepEqual(x86DirectTailSnapshot(file), before) {
		return x86DirectTailContext("resolver changed source/signatures during verification")
	}
	return nil
}
