package plan9asm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
)

// The public value transports only a private live observer binding. Neither
// a declaration, a frame size nor a JSON round trip can construct this proof.
type x86FixedLocalBinding struct {
	identity       *x86FixedLocalBinding
	source         *GoAMD64FrameSource
	context        context.Context
	file           [32]byte
	assembly       string
	target         string
	inputs         map[string][32]byte
	signatures     map[string]FuncSig
	frames         map[string]bool   // Only entries whose complete local proof succeeded.
	leaves         map[string]string // Original source symbol to observed native TEXT, never a signature.
	symbols        map[string]string
	declarations   map[string]goAMD64FrameDeclaration
	numericalReads *GoX86NumericalReadBinding
	literalData    map[string]x86FixedLocalData
	globals        map[string]goReadOnlyObject
}

// BindFixedLocal binds a complete original typed ABI0 file to its actual Go
// object observation. It does not support dynamic incoming frames, pointees,
// imported declarations, native entries or arbitrary local-memory effects.
// The returned Options are independent copies; their private signatures may
// also be transported by GoModuleOptions.ManualSig. The capture context must
// remain live through translation. Close or any failed Verify revokes them.
func (source *GoAMD64FrameSource) BindFixedLocal(ctx context.Context, pkg GoPackage, file *File, options Options) (Options, error) {
	if err := source.Verify(ctx); err != nil {
		return Options{}, err
	}
	if file == nil || options.ResolveSym == nil {
		return Options{}, goAMD64FrameContext("fixed local binding needs complete source and symbol resolution")
	}
	originalOptions := options
	numerical := options.NumericalReads
	if numerical != nil {
		if err := verifyNumericalReadInputs(file, options); err != nil {
			return Options{}, err
		}
		source.mu.Lock()
		joined := source.numericalBinding == numerical
		source.mu.Unlock()
		if !joined || ctx != numerical.context || pkg.Types != numerical.originalTypes ||
			!numericalSameImports(pkg.Imports, numerical.originalImports) {
			return Options{}, goAMD64FrameContext("fixed local source has a foreign numerical read owner")
		}
	}
	// Never execute a caller callback while holding the observer lock. Freeze
	// its answers before the locked full-source/declaration comparison; that
	// comparison rejects any mutation made while resolving these names.
	resolved := make(map[string]string, len(file.Funcs))
	for _, fn := range file.Funcs {
		resolved[fn.Sym] = options.ResolveSym(fn.Sym)
	}
	for _, global := range file.Globl {
		if name, valid := fixedLocalDataSymbol(global.Sym); valid {
			resolved[name] = options.ResolveSym(name)
		}
	}
	for symbol := range fixedLocalGlobalSymbols(file) {
		resolved[symbol] = options.ResolveSym(symbol)
	}
	options.ResolveSym = func(symbol string) string { return resolved[symbol] }
	if numerical != nil {
		// The caller has been checked; the locked observation consumes only
		// sealed answers, without re-entering numerical/owner callbacks.
		options.ResolveSym = numerical.resolve
	}
	// ResolveSym may change the caller's lifetime. Sample its context only
	// outside the observer lock and retain the original, not this temporary
	// standard command context, in every returned private binding.
	private, contextErr := captureGoAMD64FramePrivateContext(ctx)
	if contextErr != nil {
		source.mu.Lock()
		source.ready = false
		source.mu.Unlock()
		return Options{}, errors.Join(goAMD64FrameContext("fixed local caller context expired"), contextErr)
	}
	defer private.stop()
	source.mu.Lock()
	bound, err := source.bindFixedLocalLocked(private, ctx, pkg, file, options)
	source.mu.Unlock()
	if contextErr := private.verify(); contextErr != nil {
		source.mu.Lock()
		source.ready = false
		source.mu.Unlock()
		return Options{}, errors.Join(err, goAMD64FrameContext("fixed local caller context expired"), contextErr)
	}
	if err != nil {
		return Options{}, err
	}
	if err := source.Verify(ctx); err != nil {
		return Options{}, err
	}
	if numerical != nil {
		if err := verifyNumericalReadInputs(file, originalOptions); err != nil {
			return Options{}, err
		}
		// Bind a fresh numerical token to the independently established local
		// capability. The frame keeps its original token; no token is mutated.
		bound.NumericalReads = nil
		return numerical.source.BindNumericalReads(ctx, pkg, file, bound)
	}
	return bound, nil
}

func (source *GoAMD64FrameSource) bindFixedLocalLocked(ctx context.Context, lifetime context.Context, pkg GoPackage, file *File, options Options) (Options, error) {
	if !source.ready || ctx == nil || ctx.Err() != nil || file == nil || file.Arch != ArchAMD64 ||
		options.Goarch != "amd64" || pkg.Types == nil || pkg.Path != source.selection.ImportPath || pkg.Types.Path() != pkg.Path {
		return Options{}, goAMD64FrameContext("fixed local binding has no matching live package/target")
	}
	targets := map[string]string{
		"x86_64-unknown-linux-gnu": "linux/amd64",
		"x86_64-apple-darwin":      "darwin/amd64",
		"x86_64-apple-macosx":      "darwin/amd64",
		"x86_64-pc-windows-msvc":   "windows/amd64",
		"x86_64-w64-windows-gnu":   "windows/amd64",
	}
	if targets[options.TargetTriple] != source.request.Target || options.WASMABI != WASMABIDirect ||
		len(file.UnlinkedPrelude)+len(options.X86TailGroups) != 0 {
		return Options{}, goAMD64FrameContext("fixed local binding target or complete source roles disagree")
	}
	original, err := goAMD64FrameRead(filepath.Join(source.request.Directory, source.request.AssemblyFile))
	if err != nil {
		return Options{}, err
	}
	expanded, err := source.preprocess(source.request.AssemblyFile, original)
	if err != nil {
		return Options{}, err
	}
	actual, err := ParseWithDefines(ArchAMD64, expanded, nil)
	if err != nil {
		return Options{}, err
	}
	fingerprint, err := x86CallerSourceFingerprint(actual)
	if err != nil {
		return Options{}, err
	}
	provided, err := x86CallerSourceFingerprint(file)
	if err != nil || provided != fingerprint {
		return Options{}, goAMD64FrameContext("fixed local binding requires the exact full original parsed file")
	}
	resolve := options.ResolveSym
	if resolve == nil {
		return Options{}, goAMD64FrameContext("fixed local binding needs actual package symbol resolution")
	}
	globals, err := fixedLocalGlobalRequests(pkg, actual, resolve)
	if err != nil {
		return Options{}, err
	}
	declarations, err := source.typedDeclarationsForSourceRole(pkg, false, "amd64", false, nil, false, globals)
	if err != nil {
		return Options{}, err
	}
	binding := &x86FixedLocalBinding{
		source:         source,
		context:        lifetime,
		file:           fingerprint,
		assembly:       expanded,
		target:         options.TargetTriple,
		inputs:         make(map[string][32]byte, len(source.inputs)),
		signatures:     make(map[string]FuncSig),
		frames:         make(map[string]bool),
		leaves:         make(map[string]string),
		symbols:        make(map[string]string),
		declarations:   make(map[string]goAMD64FrameDeclaration),
		numericalReads: options.NumericalReads,
		globals:        globals,
	}
	binding.identity = binding
	literalData, dataSymbols, err := source.fixedLocalData(actual, expanded, resolve)
	if err != nil {
		return Options{}, err
	}
	binding.literalData = literalData
	for symbol, name := range dataSymbols {
		binding.symbols[symbol] = name
	}
	for symbol, object := range globals {
		binding.symbols[symbol] = object.native
	}
	if options.NumericalReads != nil {
		if err := joinNumericalReadCertificates(actual, options); err != nil {
			return Options{}, err
		}
	}
	for name, sum := range source.inputs {
		binding.inputs[name] = sum
	}
	options.Sigs, err = cloneFixedLocalSigs(options.Sigs)
	if err != nil {
		return Options{}, err
	}
	actualSignatures, err := cloneFixedLocalSigs(options.Sigs)
	if err != nil {
		return Options{}, err
	}
	leafSources := make(map[string]string)
	for name, observed := range source.functions {
		if observed.privateLeaf {
			leafSources[observed.sourceSymbol] = name
		}
	}
	for _, fn := range actual.Funcs {
		name := resolve(fn.Sym)
		if native, leaf := leafSources[fn.Sym]; leaf {
			if _, supplied := options.Sigs[name]; supplied || name == "" {
				return Options{}, goAMD64FrameContext("private leaf cannot acquire a supplied callable signature")
			}
			binding.leaves[fn.Sym], binding.symbols[fn.Sym] = native, name
			continue
		}
		observed, found := source.functions[name]
		declaration, declared := declarations[name]
		expectedName := pkg.Path + "." + strings.TrimPrefix(fn.Sym, "·")
		sig, supplied := options.Sigs[name]
		if !found || !supplied || name != expectedName || len(observed.code) == 0 ||
			observed.locals != goAMD64FrameNativeLocals(fn.FrameSize) || observed.args != fn.ArgSize ||
			!reflect.DeepEqual(sig, observed.signature) || !declared ||
			!source.matchesFixedLocalDeclaration(name, declaration) {
			return Options{}, goAMD64FrameContext("fixed local actual declaration/object/symbol mismatch: %s", fn.Sym)
		}
		if fn.FrameSize > 0 {
			binding.frames[name] = true
			sig.x86FixedLocal = binding
		}
		binding.signatures[name] = actualSignatures[name]
		// Preserve the independently re-typechecked language identity, not
		// merely the collapsed LLVM signature. Neither observation-only
		// composite roles nor stale private metadata can replace this witness.
		declaration.signature = actualSignatures[name]
		binding.declarations[name] = declaration
		binding.symbols[fn.Sym] = name
		options.Sigs[name] = sig
	}
	if len(options.Sigs)+len(binding.leaves) != len(actual.Funcs) {
		return Options{}, goAMD64FrameContext("fixed local complete entry/leaf signature inventory differs")
	}
	if len(binding.frames) == 0 {
		return Options{}, goAMD64FrameContext("complete source has no private fixed frame to bind")
	}
	graph, err := newX86FixedLocalLeafGraph(actual, options, binding)
	if err != nil {
		return Options{}, err
	}
	for _, fn := range actual.Funcs {
		name := binding.symbols[fn.Sym]
		if !binding.frames[name] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return Options{}, err
		}
		if _, err := proveX86FixedLocalRoot(fn, options.Sigs[name], graph); err != nil {
			return Options{}, err
		}
	}
	return options, nil
}

// After validating mutable public input, consume only independent immutable
// copies. A stateful resolver or a mutation of the caller's Options map cannot
// change the declaration or function name between normalization and emission.
func freezeX86FixedLocalOptions(options Options, bindings []*x86FixedLocalBinding) (Options, error) {
	if len(bindings) == 0 {
		return options, nil
	}
	symbols := make(map[string]string)
	options.Sigs = make(map[string]FuncSig)
	for _, binding := range bindings {
		for symbol, name := range binding.symbols {
			symbols[symbol] = name
		}
		signatures, err := cloneFixedLocalSigs(binding.signatures)
		if err != nil {
			return Options{}, err
		}
		for name, sig := range signatures {
			if binding.frames[name] {
				sig.x86FixedLocal = binding
			}
			options.Sigs[name] = sig
		}
	}
	options.ResolveSym = func(symbol string) string {
		if name, found := symbols[symbol]; found {
			return name
		}
		if options.NumericalReads != nil {
			return options.NumericalReads.resolve(symbol)
		}
		return symbol // No source contract admits external calls or addresses.
	}
	return options, nil
}

func freezeX86FixedLocalFile(file *File, bindings []*x86FixedLocalBinding) (*File, error) {
	if len(bindings) == 0 {
		return file, nil
	}
	if len(bindings) != 1 {
		return nil, goAMD64FrameContext("fixed local complete file has multiple source owners")
	}
	binding := bindings[0]
	fingerprint, err := x86CallerSourceFingerprint(file)
	if err != nil || fingerprint != binding.file {
		return nil, goAMD64FrameContext("fixed local resolver changed the original source during validation")
	}
	// Parsing the guarded observer's immutable expanded bytes gives the
	// consumer independent Func/Instr/Operand slices with no caller aliases
	// or pre-existing private certificates.
	actual, err := ParseWithDefines(ArchAMD64, binding.assembly, nil)
	if err != nil {
		return nil, err
	}
	fingerprint, err = x86CallerSourceFingerprint(actual)
	if err != nil || fingerprint != binding.file {
		return nil, goAMD64FrameContext("fixed local sealed source snapshot changed")
	}
	if graph := file.x86DirectTails; graph != nil && graph.fixedLocal == binding {
		actual.x86DirectTails = graph // Same verified complete source, fresh instruction slices.
	}
	return actual, nil
}

func cloneFixedLocalSigs(input map[string]FuncSig) (map[string]FuncSig, error) {
	// The source signatures are JSON-encodable public ABI metadata. Reusing
	// neither caller slices nor nested FrameSlot fields prevents mutation leaks.
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, goAMD64FrameContext("fixed local declaration cannot be independently copied: %v", err)
	}
	var result map[string]FuncSig
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, goAMD64FrameContext("fixed local declaration copy cannot be decoded: %v", err)
	}
	return result, nil
}

func verifyX86FixedLocalBindings(file *File, options Options) ([]*x86FixedLocalBinding, error) {
	var bindings []*x86FixedLocalBinding
	seen := make(map[*x86FixedLocalBinding]bool)
	for _, sig := range options.Sigs {
		binding := sig.x86FixedLocal
		if binding == nil || seen[binding] {
			continue
		}
		seen[binding] = true
		if file == nil || file.Arch != ArchAMD64 || options.Goarch != "amd64" || options.TargetTriple != binding.target ||
			options.ResolveSym == nil || options.WASMABI != WASMABIDirect || len(options.X86TailGroups) != 0 {
			return nil, goAMD64FrameContext("fixed local consumer target or resolver changed")
		}
		if err := binding.verify(); err != nil {
			return nil, err
		}
		if binding.numericalReads != nil && (options.NumericalReads == nil ||
			options.NumericalReads.source != binding.numericalReads.source ||
			options.NumericalReads.context != binding.context) {
			return nil, goAMD64FrameContext("fixed local numerical consumer has a foreign source/context")
		}
		fingerprint, err := x86CallerSourceFingerprint(file)
		if err != nil || fingerprint != binding.file || len(options.Sigs) != len(binding.signatures) {
			return nil, goAMD64FrameContext("fixed local consumer original/normalized source changed")
		}
		for _, fn := range file.Funcs {
			name := options.ResolveSym(fn.Sym)
			if _, leaf := binding.leaves[fn.Sym]; leaf {
				if _, supplied := options.Sigs[name]; supplied || name != binding.symbols[fn.Sym] {
					return nil, goAMD64FrameContext("private leaf consumer changed its non-callable identity")
				}
				continue
			}
			actual, found := options.Sigs[name]
			expected, declared := binding.signatures[name]
			var frame *x86FixedLocalBinding
			if binding.frames[name] {
				frame = binding
			}
			actual.x86FixedLocal = nil
			if !found || !declared || name != binding.symbols[fn.Sym] || !reflect.DeepEqual(actual, expected) ||
				options.Sigs[name].x86FixedLocal != frame {
				return nil, goAMD64FrameContext("fixed local consumer declaration or unique symbol binding changed")
			}
		}
		for _, global := range file.Globl {
			name, private := fixedLocalDataSymbol(global.Sym)
			if !private || options.ResolveSym(name) != binding.symbols[name] {
				return nil, goAMD64FrameContext("fixed local consumer literal symbol resolution changed")
			}
		}
		for symbol, object := range binding.globals {
			if options.ResolveSym(symbol) != object.native {
				return nil, goAMD64FrameContext("fixed local consumer Go variable resolution changed")
			}
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func (binding *x86FixedLocalBinding) verify() error {
	if binding == nil || binding.identity != binding || binding.source == nil {
		return goAMD64FrameContext("missing or expired fixed local observer binding")
	}
	if err := binding.source.Verify(binding.context); err != nil {
		return err
	}
	binding.source.mu.Lock()
	defer binding.source.mu.Unlock()
	if !binding.source.ready || !reflect.DeepEqual(binding.inputs, binding.source.inputs) {
		return goAMD64FrameContext("fixed local observer identity changed or was revoked")
	}
	if len(binding.declarations) != len(binding.signatures) || len(binding.frames) == 0 {
		return goAMD64FrameContext("fixed local typed language witnesses are incomplete")
	}
	for name, signature := range binding.signatures {
		declaration, found := binding.declarations[name]
		if !found || !reflect.DeepEqual(signature, declaration.signature) ||
			!binding.source.matchesFixedLocalDeclaration(name, declaration) ||
			binding.frames[name] != (binding.source.functions[name].locals > 0) {
			return goAMD64FrameContext("fixed local typed language/object identity changed: %s", name)
		}
	}
	for symbol, native := range binding.leaves {
		fn, found := binding.source.functions[native]
		if !found || !fn.privateLeaf || fn.sourceSymbol != symbol || fn.signature.Name != "" {
			return goAMD64FrameContext("private leaf original machine identity changed")
		}
	}
	return nil
}

// Called only while source.mu is held. The expected declaration comes from
// an independent original-source typecheck at Bind, then a private deep copy
// retained by that binding. A factory observation alone grants no permission.
func (source *GoAMD64FrameSource) matchesFixedLocalDeclaration(name string, expected goAMD64FrameDeclaration) bool {
	observed, found := source.functions[name]
	original, declared := source.declarations[name]
	return found && declared && fixedLocalTransportRole(expected.transport) &&
		observed.transport == expected.transport && original.transport == expected.transport &&
		expected.languageType != "" && observed.languageType == expected.languageType &&
		original.languageType == expected.languageType &&
		reflect.DeepEqual(observed.signature, expected.signature) && reflect.DeepEqual(original.signature, expected.signature)
}

func finishX86FixedLocalBindings(bindings []*x86FixedLocalBinding) error {
	for _, binding := range bindings {
		if err := binding.verify(); err != nil {
			return fmt.Errorf("fixed local post-consumption verification: %w", err)
		}
	}
	return nil
}

// Use a digest of the complete public instruction shape; private certificates
// are not serialized and cannot self-authenticate a modified instruction.
func fixedLocalInstructionDigest(ins Instr) ([32]byte, error) {
	encoded, err := json.Marshal(ins)
	if err != nil {
		return [32]byte{}, goAMD64FrameContext("fixed local instruction cannot be bound: %v", err)
	}
	return sha256.Sum256(encoded), nil
}
