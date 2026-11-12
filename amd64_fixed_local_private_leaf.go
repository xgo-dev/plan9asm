package plan9asm

// Both consumers share the source graph, callsite expansion and per-root
// limits. Total work may span more roots; the authenticated source inventory
// and each proof's work bounds remain unchanged. Memory and result facts still
// come from the existing fixed-local transfer and replay.
func newX86FixedLocalLeafGraph(file *File, options Options, binding *x86FixedLocalBinding) (*x86DirectTailGraph, error) {
	if len(binding.leaves) == 0 {
		return nil, nil
	}
	helpers := make(map[string]bool, len(binding.leaves))
	for symbol := range binding.leaves {
		helpers[symbol] = true
	}
	graph, byName, err := newX86DirectTailGraph(file, options, helpers, "amd64")
	if err != nil {
		return nil, err
	}
	graph.fixedLocal = binding
	reached := make(map[string]bool)
	for index, fn := range graph.original.Funcs {
		if helpers[fn.Sym] || !x86DirectTailRootTargets(fn, helpers, nil) {
			continue
		}
		if !binding.frames[graph.symbols[fn.Sym]] {
			return nil, goAMD64FrameContext("private leaf caller lacks its independently observed nonzero root frame")
		}
		view, err := graph.root(index, byName, 4096, true)
		if err != nil {
			return nil, err
		}
		// Keep only the original root identity. Each consumer expands one root
		// in its own function scope; the complete source is never cropped.
		graph.roots[fn.Sym] = &x86DirectTailRoot{graph: graph, text: index}
		for _, point := range view.points {
			reached[graph.original.Funcs[point.text].Sym] = true
		}
	}
	for symbol := range helpers {
		if !reached[symbol] {
			return nil, goAMD64FrameContext("observed private leaf has no complete framed caller")
		}
	}
	return graph, nil
}

// The shared constructor still checks the 4096-node limit before allocating.
// Its returned view is local to one proof/renderer/reference operation, never
// installed in the complete file or retained in the graph's root directory.
func (graph *x86DirectTailGraph) fixedLocalRoot(symbol string) (*x86DirectTailRoot, error) {
	if graph == nil || graph.fixedLocal == nil {
		return nil, nil
	}
	root := graph.roots[symbol]
	if root == nil {
		return nil, nil
	}
	if graph.revoked.Load() || root.graph != graph || root.text < 0 || root.text >= len(graph.original.Funcs) ||
		graph.original.Funcs[root.text].Sym != symbol {
		return nil, goAMD64FrameContext("private leaf original root identity changed")
	}
	return graph.root(root.text, graph.texts, 4096, true)
}

func proveX86FixedLocalRoot(fn Func, sig FuncSig, graph *x86DirectTailGraph) (Func, error) {
	view, err := graph.fixedLocalRoot(fn.Sym)
	if err != nil {
		return fn, err
	}
	fn.x86DirectTailRoot = view
	return proveX86FixedLocal(fn, sig)
}

func prepareX86FixedLocalLeafSource(file *File, options Options) (*File, bool, error) {
	for _, sig := range options.Sigs {
		binding := sig.x86FixedLocal
		if binding == nil || len(binding.leaves) == 0 {
			continue
		}
		if graph := file.x86DirectTails; graph != nil {
			if graph.fixedLocal != binding {
				return nil, true, goAMD64FrameContext("private leaf graph belongs to another frame owner")
			}
			return file, true, graph.verify(file, options)
		}
		if _, err := verifyX86FixedLocalBindings(file, options); err != nil {
			return nil, true, err
		}
		graph, err := newX86FixedLocalLeafGraph(file, options, binding)
		if err != nil {
			return nil, true, err
		}
		request := x86DirectTailSnapshot(file)
		request.x86DirectTails = graph
		return request, true, graph.verify(request, options)
	}
	return file, false, nil
}

func fixedLocalProofFunction(fn Func) Func {
	if view := fn.x86DirectTailRoot; view != nil {
		fn.Instrs = view.instructions
	}
	return fn
}

// Selection only: the live fixed-local binder and full replay still validate
// this caller. Its canonical result must not be reclassified as a custom call.
func fixedLocalPrivateLeafCaller(fn Func, sig FuncSig) bool {
	binding := sig.x86FixedLocal
	return binding != nil && len(binding.leaves) != 0 && binding.frames[sig.Name] && binding.symbols[fn.Sym] == sig.Name
}

// Signature selection only. A transported real root binding identifies which
// source TEXTs must remain non-callable; the complete live binding is still
// verified before preparation/lowering and cannot be manufactured by a name.
func goFixedLocalLeafSymbols(file *File, resolve func(string) string, manual func(string) (FuncSig, bool)) map[string]bool {
	if manual == nil {
		return nil
	}
	var leaves map[string]bool
	for _, fn := range file.Funcs {
		name := resolve(goTextSymbolForResolution(fn.Sym))
		sig, supplied := goLookupManualSig(manual, name)
		if !supplied || !fixedLocalPrivateLeafCaller(fn, sig) {
			continue
		}
		if leaves == nil {
			leaves = make(map[string]bool)
		}
		for symbol := range sig.x86FixedLocal.leaves {
			leaves[symbol] = true
		}
	}
	return leaves
}
