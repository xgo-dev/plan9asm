package plan9asm

import (
	"path/filepath"
	"reflect"
)

// Fixed-local physical SP and its initialized result already have a complete
// native source/CFG proof. Revalidate that exact role instead of reinterpreting
// its private access annotations as logical AUTO bytes. A proof pointer alone
// is not permission, and this route supplies no new native/caller capability.
func (c *amd64Ctx) checkFixedLocalResultInitialization() error {
	fn, sig, proof := c.fpScalarSource, c.fpSourceSig, c.fixedLocal
	binding := sig.x86FixedLocal
	fail := func(reason string) error { return goAMD64FrameContext("fixed local result consumer: %s", reason) }
	if binding == nil || proof == nil || fn.x86FixedLocal != proof || proof.binding != binding ||
		c.goarch != "amd64" || c.targetTriple != binding.target || fn.FrameSize != proof.frame || c.frameSize != fn.FrameSize {
		return fail("source/proof/target/frame role differs")
	}
	fn = fixedLocalProofFunction(fn)
	if c.fixedLocalResult == nil {
		if err := binding.verify(); err != nil {
			return err
		}
	}
	emitted := c.sig
	emitted.Attrs = sig.Attrs // Checked against the actual complete renderer inventory below.
	if !reflect.DeepEqual(emitted, sig) {
		return fail("emitted logical signature differs from the original declaration")
	}
	expected, declared := binding.signatures[binding.symbols[fn.Sym]]
	sig.x86FixedLocal = nil
	if !declared || !reflect.DeepEqual(sig, expected) {
		return fail("actual declaration/signature differs")
	}
	sig.x86FixedLocal = binding
	snapshot := c.fixedLocalResult
	if snapshot == nil {
		var err error
		snapshot, err = newX86FixedLocalResultSnapshot(binding, c.goarch)
		if err != nil {
			return err
		}
	}
	if snapshot.binding != binding || snapshot.file != binding.file {
		return fail("complete source snapshot belongs to a different binding")
	}
	original, valid := snapshot.functions[sig.Name]
	if !valid || c.sig.Attrs != original.attributes || c.fpFeatureAttrs != original.inferred {
		return fail("emitted attributes are not the exact complete-source renderer projection")
	}
	fingerprint, err := x86CallerSourceFingerprint(fn)
	if err != nil || fingerprint != proof.function {
		return fail("complete normalized function fingerprint differs")
	}
	plain := fn
	plain.Instrs = append([]Instr(nil), fn.Instrs...)
	for ordinal, ins := range fn.Instrs {
		if len(ins.x86FixedLocalMemory) != len(proof.accesses[ordinal]) {
			return fail("instruction access inventory differs")
		}
		for operand, access := range ins.x86FixedLocalMemory {
			_, valid := c.fixedLocalMemoryAccess(ins, operand)
			if access.ordinal != ordinal || !valid {
				return fail("instruction access owner/shape/ordinal differs")
			}
		}
		plain.Instrs[ordinal].x86FixedLocalMemory = nil
	}
	for ordinal := range proof.accesses {
		if ordinal < 0 || ordinal >= len(fn.Instrs) {
			return fail("access ordinal is outside the complete function")
		}
	}
	instructions, err := x86ResultAUTOReplayInstructions(plain, c.goarch)
	if err != nil {
		return err
	}
	reference := original.function
	view, err := original.graph.fixedLocalRoot(reference.Sym)
	if err != nil {
		return err
	}
	if view != nil {
		actual := fn.x86DirectTailRoot
		if actual == nil || view.text != actual.text || !reflect.DeepEqual(view.points, actual.points) ||
			!reflect.DeepEqual(view.ordinals, actual.ordinals) || !reflect.DeepEqual(view.edges, actual.edges) ||
			!reflect.DeepEqual(view.externalTails, actual.externalTails) {
			return fail("original private root control/source coordinates differ")
		}
		reference = view.features()
	} else if fn.x86DirectTailRoot != nil {
		return fail("ordinary source acquired a private root view")
	}
	if reference.Sym != fn.Sym || reference.FrameSize != fn.FrameSize ||
		reference.ArgSize != fn.ArgSize || !reflect.DeepEqual(reference.Instrs, instructions) {
		return fail("original TEXT/source instruction roles differ")
	}
	replayed, err := proveX86FixedLocal(plain, sig)
	if err != nil {
		return err
	}
	for ordinal, accesses := range proof.accesses {
		if len(accesses) != len(replayed.x86FixedLocal.accesses[ordinal]) {
			return fail("recomputed access inventory differs")
		}
		for operand, access := range accesses {
			recomputed, found := replayed.x86FixedLocal.accesses[ordinal][operand]
			access.owner, recomputed.owner = nil, nil // Compare effects, not new builder identity.
			if !found || !reflect.DeepEqual(access, recomputed) {
				return fail("recomputed access byte effects differ")
			}
		}
	}
	if len(proof.accesses) != len(replayed.x86FixedLocal.accesses) {
		return fail("recomputed function access inventory differs")
	}
	if c.fixedLocalResult == nil {
		return binding.verify()
	}
	return nil
}

// A module-call-local index of independently parsed source, not a live source
// verification result or a new permission. Only the module's existing complete
// pre/post guards permit sharing it between function consumers. Standalone
// consumers construct their own index inside the original live guards.
type x86FixedLocalResultSnapshot struct {
	binding   *x86FixedLocalBinding
	file      [32]byte
	functions map[string]x86FixedLocalResultFunction
}

type x86FixedLocalResultFunction struct {
	function   Func
	graph      *x86DirectTailGraph // Original source/indices only; no retained expansion.
	attributes string
	inferred   string
}

func newX86FixedLocalResultSnapshot(binding *x86FixedLocalBinding, arch string) (*x86FixedLocalResultSnapshot, error) {
	fail := func(reason string) (*x86FixedLocalResultSnapshot, error) {
		return nil, goAMD64FrameContext("fixed local result consumer: %s", reason)
	}
	if binding == nil || binding.source == nil {
		return fail("missing complete original source binding")
	}
	// Replay actual guarded CPP, not a mutually consistent replacement of the
	// binding's private assembly/fingerprint. No caller callback runs under mu.
	binding.source.mu.Lock()
	if !binding.source.ready {
		binding.source.mu.Unlock()
		return fail("original source is closed or revoked")
	}
	original, err := binding.source.read(filepath.Join(binding.source.request.Directory, binding.source.request.AssemblyFile))
	var expanded string
	if err == nil {
		expanded, err = binding.source.preprocess(binding.source.request.AssemblyFile, original)
	}
	binding.source.mu.Unlock()
	if err != nil || expanded != binding.assembly {
		return fail("expanded assembly differs from the actual guarded source")
	}
	actual, err := Parse(ArchAMD64, expanded)
	if err != nil {
		return fail("complete original assembly cannot be parsed")
	}
	fingerprint, err := x86CallerSourceFingerprint(actual)
	if err != nil || fingerprint != binding.file {
		return fail("complete original assembly fingerprint differs")
	}
	functions, valid := fixedLocalResultFunctions(actual, binding, arch)
	if !valid {
		return fail("complete source feature inventory is missing or ambiguous")
	}
	return &x86FixedLocalResultSnapshot{binding: binding, file: fingerprint, functions: functions}, nil
}

// Reproduce the renderer's complete source-order feature allocation once. The
// reference spelling alone is not proof, and supplied attributes never pass
// through the inference registry or become a removable source difference.
func fixedLocalResultFunctions(file *File, binding *x86FixedLocalBinding, arch string) (map[string]x86FixedLocalResultFunction, bool) {
	if len(binding.leaves) != 0 {
		signatures, err := cloneFixedLocalSigs(binding.signatures)
		if err != nil {
			return nil, false
		}
		for name, sig := range signatures {
			if binding.frames[name] {
				sig.x86FixedLocal = binding
				signatures[name] = sig
			}
		}
		options := Options{Goarch: arch, Sigs: signatures,
			ResolveSym: func(symbol string) string { return binding.symbols[symbol] }}
		graph, err := newX86FixedLocalLeafGraph(file, options, binding)
		if err != nil {
			return nil, false
		}
		copy := *file
		copy.x86DirectTails = graph
		file = &copy
	}
	registry := newFeatureAttrRegistry()
	functions := make(map[string]x86FixedLocalResultFunction, len(file.Funcs))
	for _, fn := range file.Funcs {
		if file.x86DirectTailHelper(fn.Sym) {
			continue
		}
		resolved, found := binding.symbols[fn.Sym]
		sig, declared := binding.signatures[resolved]
		_, duplicate := functions[resolved]
		if !found || !declared || duplicate || len(fn.X86RawText) != 0 || amd64IsRelocationAnchor(fn, sig) {
			return nil, false
		}
		features := fn
		view, err := file.x86DirectTails.fixedLocalRoot(fn.Sym)
		if err != nil {
			return nil, false
		}
		if view != nil {
			features = view.features()
		}
		derived := ""
		if sig.Attrs == "" {
			derived = registry.ref(inferFuncTargetFeaturesForGOARCH(file.Arch, arch, features))
		}
		attributes := sig.Attrs
		if attributes == "" {
			attributes = derived
		}
		functions[resolved] = x86FixedLocalResultFunction{
			function: fn, graph: file.x86DirectTails, attributes: attributes, inferred: derived,
		}
	}
	return functions, true
}
