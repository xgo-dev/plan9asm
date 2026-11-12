package plan9asm

import (
	"reflect"
	"strings"
)

// This plan proves the root's actual canonical byte through its complete
// original helper graph. Helpers retain their independent Void/ArgRegs ABI;
// no helper receives a copied root frame or an invented I1 result.
type x86CustomHelperBoolTail struct {
	view    *x86DirectTailRoot
	helpers map[string]FuncSig
	proved  bool
}

func x86CustomHelperBoolFrameRole(fn Func, sig FuncSig, arch string) bool {
	plan := fn.x86BoolCalls
	if arch != "386" || plan == nil || plan.registerTail == nil || !x86ABI0BoolDeclarationRole(sig, arch) ||
		fn.x86DirectTailRoot != nil && fn.x86DirectTailRoot != plan.registerTail.view {
		return false
	}
	fn.x86DirectTailRoot = nil // Only compare this proof view with its exact original root.
	end := sig.Frame.Results[0].Offset + 1
	return fn.FrameSize == 0 && (fn.ArgSize == end || fn.ArgSize == (end+3)&^3) && plan.matches(fn, sig, arch)
}

func (source *x86ABI0BoolCallSource) prepareCustomRegisterTail(plan *x86ABI0BoolCallPlan) error {
	fail := func(reason string) error { return x86ABI0BoolCallContext("custom register tail: " + reason) }
	if source.options.Goarch != "386" || !x86ABI0BoolDeclarationRole(plan.signature, "386") || plan.function.FrameSize != 0 ||
		source.options.NumericalReads != nil || source.options.X86TLSMoves != nil || source.options.ARM64ByteCarrierSource != nil ||
		len(source.options.X86TailGroups) != 0 || len(source.original.UnlinkedPrelude) != 0 || len(source.original.x86Continuations) != 0 {
		return fail("root or native/source role is not closed")
	}
	if source.customGraph == nil {
		helpers := make(map[string]bool)
		for _, fn := range source.original.Funcs {
			if strings.HasSuffix(fn.Sym, "<>") {
				helpers[fn.Sym] = true
			}
		}
		graph, _, err := newX86DirectTailGraph(source.origin, source.options, helpers, "386")
		if err != nil {
			return err
		}
		source.customGraph = graph
	}
	graph := source.customGraph
	byName := make(map[string]int)
	for index, fn := range graph.original.Funcs {
		byName[fn.Sym] = index
	}
	root, found := byName[plan.function.Sym]
	if !found {
		return fail("root is absent from the original graph")
	}
	combined := 0
	for _, prior := range graph.roots {
		combined += len(prior.points)
	}
	view, err := graph.root(root, byName, 4096-combined, false)
	if err != nil {
		return err
	}
	tail := &x86CustomHelperBoolTail{view: view, helpers: make(map[string]FuncSig)}
	for _, point := range view.points {
		fn := graph.original.Funcs[point.text]
		if point.text == root {
			continue
		}
		if _, checked := tail.helpers[fn.Sym]; checked {
			continue
		}
		name := graph.symbols[fn.Sym]
		sig, declared := graph.signatures[name]
		if !declared || sig.Name != "" && sig.Name != name || !x86CustomHelperBoolSignature(sig) {
			return fail("helper lacks its complete explicit Void/register declaration")
		}
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				if arg.Kind == OpFP || arg.Kind == OpFPAddr {
					return fail("a custom helper cannot borrow the root FP layout")
				}
			}
		}
		tail.helpers[fn.Sym] = sig
	}
	if len(tail.helpers) == 0 {
		return fail("complete private helper graph is missing")
	}
	for _, external := range view.externalTails {
		if external {
			return fail("external terminal needs its independent canonical result contract")
		}
	}
	if !tail.acyclicCalls() {
		return fail("cyclic custom calls cannot borrow continuation stack behavior")
	}
	graph.roots[plan.function.Sym] = view
	plan.registerTail = tail
	fn := plan.function
	fn.x86DirectTailRoot, fn.x86BoolCalls, fn.x86ResultFlowBudget = view, plan, &source.budget
	if !x86CustomHelperBoolFrameRole(fn, plan.signature, "386") {
		return fail("root extent disagrees with its actual declared byte")
	}
	if err := plan.replay(); err != nil {
		return err
	}
	if err := checkX86ABI0ResultInitializationAtSource(fn, plan.signature, "386",
		func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
			// These complete scalar load/extension families use the existing
			// exact-width volatile emitters. A continued read defines only its
			// numerical result, never pointee extent or a reusable memory role.
			if accepted, known := x86LoweredScalarNativeLoad(ins, state, owned, resultOffset, arch); known {
				return accepted
			}
			if accepted, known := x86LoweredScalarExtensionRead(ins, state, owned, resultOffset, arch); known {
				return accepted
			}
			if accepted, known := x86LoweredLegacyPackedMoveRead(ins, state, owned, resultOffset, arch); known {
				return accepted
			}
			if !x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch) {
				return false
			}
			return tail.transport(ins, state, resultOffset, arch)
		}, true); err != nil {
		return err
	}
	tail.proved = true
	return nil
}

func x86CustomHelperBoolSignature(sig FuncSig) bool {
	if sig.Ret != Void || len(sig.Args) == 0 || len(sig.Args) > 6 || len(sig.Args) != len(sig.ArgRegs) ||
		len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 || sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil ||
		sig.ARM64ClosureABI != nil || sig.WASMContext != "" || sig.WASMNative || sig.x86BorrowedBoolTail {
		return false
	}
	seen, pointers := make(map[Reg]bool), 0
	for index, typ := range sig.Args {
		if typ != I1 && typ != I8 && typ != I16 && typ != I32 && typ != Ptr {
			return false
		}
		reg := sig.ArgRegs[index]
		if _, _, valid := x86ResultGP(reg, 4, "386"); !valid || seen[reg] {
			return false
		}
		seen[reg] = true
		if typ == Ptr {
			pointers++
		}
	}
	return pointers != 0
}

func (tail *x86CustomHelperBoolTail) acyclicCalls() bool {
	edges := make(map[string][]string)
	for pc, ins := range tail.view.instructions {
		if ins.Op != OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
			continue
		}
		name, _, valid := parseSBRef(ins.Args[0].Sym)
		if _, helper := tail.helpers[name]; valid && helper {
			caller := tail.view.graph.original.Funcs[tail.view.points[pc].text].Sym
			edges[caller] = append(edges[caller], name)
		}
	}
	colors := make(map[string]uint8)
	var visit func(string) bool
	visit = func(name string) bool {
		if colors[name] != 0 {
			return colors[name] == 2
		}
		colors[name] = 1
		for _, next := range edges[name] {
			if !visit(next) {
				return false
			}
		}
		colors[name] = 2
		return true
	}
	for name := range tail.helpers {
		if !visit(name) {
			return false
		}
	}
	return true
}

// A real emitted custom call carries only its declared register inputs. In
// particular, caller FLAGS, undeclared GP bytes and vector state cannot seed
// the independently emitted helper. Each pointer retains its actual source
// role: an exact result-byte alias or an opaque incoming pointer. Neither role
// grants native backing or numerical address bits.
func (tail *x86CustomHelperBoolTail) transport(ins Instr, state *x86ResultState, resultOffset int64, arch string) bool {
	if ins.Op != OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
		return true
	}
	name, offset, valid := parseSBRef(ins.Args[0].Sym)
	sig, declared := tail.helpers[name]
	if !valid || offset != 0 || !declared || state.boolFrameGP == nil {
		return false
	}
	if state.valueStack != nil {
		if state.valueStack.invalid || len(state.valueStack.bytes) != 0 {
			return false
		}
		state.valueStack.id = false
	}
	var gp, canonical [16]uint8
	var pointers, addresses [16]bool
	var origins [16]uint16
	resultAlias := false
	aliases := new([16]x86ResultSlotAddress)
	for index, typ := range sig.Args {
		root, _, _ := x86ResultGP(sig.ArgRegs[index], 4, arch)
		if typ == Ptr {
			value := state.boolFrameGP[root]
			if !value.valid && !state.shapeOnly {
				if !state.pointerGP[root] || !state.callerAddressGP[root] {
					return false
				}
				pointers[root], addresses[root] = true, true
				origins[root] = state.callerAddressOrigin[root]
				continue
			}
			if state.shapeOnly && !value.valid {
				value = x86ResultSlotAddress{start: resultOffset, end: resultOffset + 1, offset: resultOffset, valid: true}
			}
			if !value.valid || value.start != resultOffset || value.end != resultOffset+1 || value.offset != resultOffset {
				return false
			}
			aliases[root] = value
			resultAlias = true
			continue
		}
		width := x86FrameScalarBytes(typ, arch)
		_, mask, _ := x86ResultGP(sig.ArgRegs[index], width, arch)
		if !state.shapeOnly && (state.gp[root]&mask != mask || state.boolFrameGP[root].valid ||
			state.pointerGP[root] || state.callerAddressGP[root] || typ == I1 && state.canonicalGP[root]&mask != mask) {
			return false
		}
		gp[root], canonical[root] = mask, state.canonicalGP[root]&mask
	}
	if !resultAlias {
		return false
	}
	state.gp, state.canonicalGP, state.boolFrameGP = gp, canonical, aliases
	state.pointerGP, state.callerAddressGP = pointers, addresses
	state.callerAddressOrigin = origins
	state.resultAddressGP = [16]x86ResultSlotAddress{}
	state.xmm, state.vectorUpper, state.masks = [32]uint16{}, [32]uint64{}, [8]bool{}
	state.flags, state.direction = 0, x86ResultDirectionUnknown
	state.bitScanPending, state.predicate = x86ResultBitScanPending{}, x86ResultPredicate{}
	return true
}

func (source *x86ABI0BoolCallSource) ownsCustomRegisterTails(file *File, options Options) (ownedResult bool, result error) {
	if source.customGraph == nil {
		return false, nil
	}
	defer func() {
		if result != nil {
			source.customGraph.revoked.Store(true)
		}
	}()
	if options.Goarch != "386" || !x86ScalarFloatIntegerNativeTarget("386", options.TargetTriple) {
		return false, x86ABI0BoolCallContext("custom register tail lost its actual 32-bit target")
	}
	owned := make(map[string]bool)
	present := make(map[string]bool)
	for _, fn := range file.Funcs {
		present[fn.Sym] = true
	}
	for _, plan := range source.callers {
		if tail := plan.registerTail; tail != nil && tail.proved {
			for helper := range tail.helpers {
				owned[helper] = true
				if present[plan.function.Sym] && !present[helper] {
					return false, x86ABI0BoolCallContext("selected root lost an actual custom helper definition")
				}
			}
		}
	}
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") && !owned[fn.Sym] {
			return false, nil
		}
		if x86DirectTailRootNeeded(fn) && !strings.HasSuffix(fn.Sym, "<>") {
			plan := source.callers[fn.Sym]
			if plan == nil || plan.registerTail == nil || !plan.registerTail.proved {
				return false, nil
			}
		}
	}
	if err := source.customGraph.verify(file, options); err != nil {
		return false, err
	}
	// Keep the actual rendering maps and selected source live through the final
	// publication checks, not merely the independently cloned proof inventory.
	source.customSelection, source.customOptions = file, options
	return true, nil
}

func (plan *x86ABI0BoolCallPlan) checkCustomRegisterTail(fn Func, sig FuncSig, arch string) error {
	if plan.registerTail == nil || !plan.registerTail.proved || !x86CustomHelperBoolFrameRole(fn, sig, arch) {
		return x86ABI0BoolCallContext("custom result-byte proof lost its original source or declaration")
	}
	return plan.source.verify()
}

// The complete graph already checks every helper instruction after transporting
// only that helper's declared inputs and exact private result-byte address.
// Reuse that proof only for its original helper and actual emitted declaration;
// a private symbol or a Void/ArgRegs signature alone grants nothing.
func (c *amd64Ctx) checkCustomHelperBoolSource() (bool, error) {
	source := c.fpBoolCallSource
	if source == nil || !strings.HasSuffix(c.fpScalarSource.Sym, "<>") {
		return false, nil
	}
	for _, plan := range source.callers {
		tail := plan.registerTail
		if tail == nil || !tail.proved {
			continue
		}
		expected, present := tail.helpers[c.fpScalarSource.Sym]
		if !present {
			continue
		}
		fail := func(reason string) (bool, error) {
			return true, x86ABI0BoolCallContext("custom helper consumer: " + reason)
		}
		if c.goarch != "386" || c.targetTriple != source.options.TargetTriple {
			return fail("actual target differs from the proved graph")
		}
		if expected.Name == "" {
			expected.Name = source.resolved[c.fpScalarSource.Sym]
		}
		emitted := expected
		if expected.Attrs == "" {
			emitted.Attrs = c.fpFeatureAttrs
		} else if c.fpFeatureAttrs != "" {
			return fail("supplied attributes acquired an inferred replacement")
		}
		if !reflect.DeepEqual(c.fpSourceSig, expected) || !reflect.DeepEqual(c.sig, emitted) {
			return fail("actual helper declaration or emitted transport differs")
		}
		for _, original := range source.original.Funcs {
			if original.Sym == c.fpScalarSource.Sym {
				if !reflect.DeepEqual(original, c.fpScalarSource) {
					return fail("complete helper source differs")
				}
				return true, source.verify()
			}
		}
		return fail("original helper TEXT is missing")
	}
	return false, nil
}
