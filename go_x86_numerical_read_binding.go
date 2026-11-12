package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// GoX86NumericalReadBinding is a live factory token, not a serializable report.
// Its capture context and every source/storage owner must remain live until
// translation completes. Failure/Close revokes the originating source.
type GoX86NumericalReadBinding struct {
	originalBinding *GoX86NumericalReadBinding
	source          *GoX86NumericalReadSource
	originalSource  *GoX86NumericalReadSource
	context         context.Context
	originalContext context.Context
	packageInput    GoPackage
	originalTypes   *types.Package
	originalImports map[string]*types.Package
	file            [32]byte
	options         Options
	symbols         map[string]string
	declarations    map[string]goAMD64FrameDeclaration
	reads           []numericalSBReadFact
	literalAccesses []x86SDKLiteralAccess
	literalMinimum  *numericalSDKLiteralMinimumJoin
	capabilities    map[string]numericalSignatureCapabilities
	seal            [32]byte
}

type numericalSignatureCapabilities struct {
	caller    *x86GoCallerRegionProof
	local     *x86FixedLocalBinding
	arguments *amd64GoArgumentBinding
}

func numericalCapabilities(sigs map[string]FuncSig) map[string]numericalSignatureCapabilities {
	result := make(map[string]numericalSignatureCapabilities, len(sigs))
	for name, sig := range sigs {
		result[name] = numericalSignatureCapabilities{sig.x86CallerRegions, sig.x86FixedLocal, sig.amd64GoArguments}
	}
	return result
}

// BindNumericalReads joins complete caller declarations/options to the sealed
// original source and actual native reads. It returns independent Options;
// declarations alone, JSON, pointer types and a numerical owner cannot bind.
func (source *GoX86NumericalReadSource) BindNumericalReads(ctx context.Context, pkg GoPackage, file *File, options Options) (Options, error) {
	return source.bindNumericalReads(ctx, pkg, file, options, nil)
}

func (source *GoX86NumericalReadSource) bindNumericalReads(ctx context.Context, pkg GoPackage, file *File, options Options, minimum *GoX86SDKLiteralAlignment) (Options, error) {
	if carrier := options.ARM64ByteCarrierSource; carrier != nil {
		source.revokeNumericalSource()
		carrier.revokeCarrier()
		return Options{}, mixedNativeAuthorityContext()
	}
	if err := source.Verify(ctx); err != nil {
		return Options{}, err
	}
	if file == nil || options.ResolveSym == nil || pkg.Types == nil || pkg.Path != source.request.PackagePath || pkg.Types.Path() != pkg.Path || pkg.SourceSelection != nil {
		return Options{}, numericalSBContext("binding lacks complete original declarations/source/resolver")
	}
	_, arch, _ := strings.Cut(source.request.Target, "/")
	triple := numericalSDKTargetTriple(source.request.Target)
	if options.Goarch != arch || options.TargetTriple != triple || options.WASMABI != WASMABIDirect || len(options.X86TailGroups) != 0 || options.NumericalReads != nil {
		return Options{}, numericalSBContext("binding profile or existing authority differs")
	}
	provided, err := x86CallerSourceFingerprint(file)
	if err != nil {
		return Options{}, err
	}
	actual, err := x86CallerSourceFingerprint(source.file)
	if err != nil || provided != actual {
		return Options{}, numericalSBContext("binding requires the exact complete original parsed file")
	}
	if source.role == numericalSBSDKSource {
		names, err := numericalGoDeclarationLinknames(pkg.Syntax, pkg.Types)
		if err != nil {
			return Options{}, err
		}
		entries, _, err := numericalTypedSourceDeclarations(file, pkg.Path, arch, source.role, names, source.native.CompilerAliases)
		if err != nil || len(entries) != len(options.Sigs) {
			return Options{}, numericalSBContext("binding typed entry/terminal inventory differs: %v", err)
		}
	} else if len(file.Funcs) != len(options.Sigs) {
		return Options{}, numericalSBContext("binding ordinary declaration inventory differs")
	}
	// Resolve outside observer locks, then verify the complete live source again.
	symbols := make(map[string]string)
	for index, fn := range file.Funcs {
		symbols[fn.Sym] = options.ResolveSym(fn.Sym)
		name, _, valid := source.numericalSourceTextIdentity(index, fn, arch)
		if strings.HasSuffix(fn.Sym, "<>") && valid {
			name = numericalNativeName(fn.Sym, pkg.Path)
			if _, fake := options.Sigs[name]; fake {
				return Options{}, numericalSBContext("private continuation cannot acquire a callable signature")
			}
		}
		if !valid || symbols[fn.Sym] != name {
			return Options{}, numericalSBContext("function resolver differs from actual original source/object ABI symbol")
		}
		logical := goTextSymbolForResolution(fn.Sym)
		if options.ResolveSym(logical) != name || symbols[logical] != "" && symbols[logical] != name {
			return Options{}, numericalSBContext("logical declaration resolver differs from its exact source/native entry")
		}
		symbols[logical] = name
	}
	tailRoles, err := numericalDirectTailRoles(file)
	if err != nil {
		return Options{}, err
	}
	for _, symbol := range tailRoles {
		name := numericalNativeName(symbol, pkg.Path)
		if options.ResolveSym(symbol) != name {
			return Options{}, numericalSBContext("continuation/terminal resolver changed exact source identity")
		}
		symbols[symbol] = name
	}
	for _, read := range source.reads {
		base, _, valid := parseSBRef(read.original.Args[read.operand].Sym)
		if !valid || options.ResolveSym(base) != read.variable.NativeName {
			return Options{}, numericalSBContext("storage resolver differs from actual typed data symbol")
		}
		symbols[base] = read.variable.NativeName
		if _, collision := options.Sigs[read.variable.NativeName]; collision {
			return Options{}, numericalSBContext("typed data symbol collides with a function")
		}
	}
	if source.literals != nil {
		if err := source.bindSDKLiteralSymbols(file, options, symbols); err != nil {
			return Options{}, err
		}
	}
	if err := source.Verify(ctx); err != nil {
		return Options{}, err
	}
	provided, err = x86CallerSourceFingerprint(file)
	if err != nil || provided != actual {
		return Options{}, numericalSBContext("binding resolver changed the complete original file")
	}
	declarationContext, stop, err := source.numericalDeclarationContext(ctx)
	if err != nil {
		return Options{}, err
	}
	defer stop()
	source.mu.Lock()
	declarations, err := source.numericalDeclarations(declarationContext, pkg, arch)
	if err == nil {
		err = numericalDeclarationSyntax(source, pkg)
	}
	source.mu.Unlock()
	if err != nil {
		return Options{}, err
	}
	sigs, err := numericalCloneSignatures(options.Sigs)
	if err != nil {
		return Options{}, err
	}
	for name, sig := range sigs {
		declaration, found := declarations[name]
		if !found || sig.amd64GoArguments != nil || sig.arm64FPReadDeclaration != nil || sig.arm64ABI0Declaration != nil || sig.arm64ABI0TailDeclaration != nil || sig.arm64NativeScratch != nil ||
			!reflect.DeepEqual(numericalSignatureShape(sig), declaration.signature) {
			return Options{}, numericalSBContext("signature is not the actual source declaration: %s", name)
		}
		if local := sig.x86FixedLocal; local != nil {
			original := local.numericalReads
			if original == nil || original.source != source || original.context != ctx ||
				original.originalTypes != pkg.Types || !numericalSameImports(pkg.Imports, original.originalImports) ||
				local.file != actual || local.target != triple || local.context != ctx {
				return Options{}, numericalSBContext("local capability has a foreign numerical source/declaration generation")
			}
			if err := local.verify(); err != nil {
				return Options{}, err
			}
		}
	}
	joinedMinimum, err := captureNumericalSDKLiteralMinimum(ctx, source, minimum)
	if err != nil {
		return Options{}, err
	}
	literalAccesses, err := source.bindSDKLiteralAccessesAtMinimum(file, sigs, symbols, arch, joinedMinimum)
	if err != nil {
		return Options{}, err
	}
	options.Sigs, options.ResolveSym = sigs, nil
	binding := &GoX86NumericalReadBinding{source: source, originalSource: source, context: ctx, originalContext: ctx, packageInput: pkg,
		originalTypes: pkg.Types, originalImports: numericalImportIdentities(pkg.Imports), file: actual,
		options: options, symbols: symbols, declarations: declarations, reads: source.readFacts(), literalAccesses: literalAccesses,
		capabilities: numericalCapabilities(sigs), literalMinimum: joinedMinimum}
	binding.originalBinding = binding
	if err := binding.bindAMD64GoArguments(); err != nil {
		return Options{}, err
	}
	binding.capabilities = numericalCapabilities(binding.options.Sigs)
	binding.seal, err = binding.digest()
	if err != nil {
		return Options{}, err
	}
	if err := binding.verify(); err != nil {
		return Options{}, err
	}
	bound := options
	bound.Sigs, err = numericalCloneSignatures(options.Sigs)
	if err != nil {
		return Options{}, err
	}
	bound.ResolveSym = binding.resolve
	bound.NumericalReads = binding
	return bound, nil
}

func numericalImportIdentities(imports map[string]*types.Package) map[string]*types.Package {
	if imports == nil {
		return nil
	}
	identities := make(map[string]*types.Package, len(imports))
	for name, pkg := range imports {
		identities[name] = pkg
	}
	return identities
}

func numericalSameImports(imports, expected map[string]*types.Package) bool {
	if (imports == nil) != (expected == nil) || len(imports) != len(expected) {
		return false
	}
	for name, pkg := range imports {
		if original, found := expected[name]; !found || pkg != original {
			return false
		}
	}
	return true
}

func numericalSignatureShape(sig FuncSig) FuncSig {
	sig.x86CallerRegions, sig.x86FixedLocal = nil, nil
	sig.amd64GoArguments = nil
	sig.arm64FPReadDeclaration, sig.arm64ABI0Declaration, sig.arm64ABI0TailDeclaration, sig.arm64NativeScratch = nil, nil, nil, nil
	return sig
}

func numericalCloneSignatures(input map[string]FuncSig) (map[string]FuncSig, error) {
	result, err := cloneFixedLocalSigs(input)
	if err != nil {
		return nil, err
	}
	// Preserve separately established private contracts, not reconstructed JSON.
	for name, old := range input {
		sig := result[name]
		sig.x86CallerRegions, sig.x86FixedLocal = old.x86CallerRegions, old.x86FixedLocal
		sig.arm64FPReadDeclaration, sig.arm64ABI0Declaration, sig.arm64ABI0TailDeclaration, sig.arm64NativeScratch = old.arm64FPReadDeclaration, old.arm64ABI0Declaration, old.arm64ABI0TailDeclaration, old.arm64NativeScratch
		sig.x86BorrowedBoolTail = old.x86BorrowedBoolTail
		sig.amd64GoArguments = old.amd64GoArguments
		result[name] = sig
	}
	return result, nil
}

func numericalDeclarationSyntax(source *GoX86NumericalReadSource, pkg GoPackage) error {
	if len(pkg.Syntax) != len(source.guard.selection.GoFiles) {
		return numericalSBContext("declaration syntax inventory differs")
	}
	wanted := make(map[string]int)
	for _, name := range source.guard.selection.GoFiles {
		data, err := source.guard.read(filepath.Join(source.request.Directory, name))
		if err != nil {
			return err
		}
		actual, err := parser.ParseFile(token.NewFileSet(), name, data, parser.ParseComments)
		if err != nil {
			return numericalSBContext("declaration syntax is missing or unparseable")
		}
		var a bytes.Buffer
		if format.Node(&a, token.NewFileSet(), actual) != nil {
			return numericalSBContext("original declaration syntax cannot be formatted")
		}
		wanted[a.String()]++
	}
	// File order and absolute token.Pos bases are not declaration semantics.
	// Compare the complete multiset, including comments/directives and bodies.
	for _, supplied := range pkg.Syntax {
		var b bytes.Buffer
		if supplied == nil || format.Node(&b, token.NewFileSet(), supplied) != nil || wanted[b.String()] == 0 {
			return numericalSBContext("supplied complete declaration syntax differs from original source")
		}
		wanted[b.String()]--
	}
	return nil
}

func (binding *GoX86NumericalReadBinding) resolve(symbol string) string {
	if name, found := binding.symbols[symbol]; found {
		return name
	}
	return symbol // No address/call role is created for unknown symbols.
}

func (binding *GoX86NumericalReadBinding) digest() ([32]byte, error) {
	arguments := make(map[string][32]byte)
	for name, sig := range binding.options.Sigs {
		if entry := sig.amd64GoArguments; entry != nil {
			digest, err := entry.digest()
			if err != nil {
				return [32]byte{}, err
			}
			arguments[name] = digest
		}
	}
	data, err := json.Marshal(struct {
		File         [32]byte
		Target, Arch string
		WASM         WASMABI
		X87          X87Mode
		Annotate     bool
		Sigs         map[string]FuncSig
		TailGroups   []X86TailGroup
		Symbols      map[string]string
		Reads        []numericalSBReadFact
		Literals     []x86SDKLiteralAccess
		Minimum      *numericalSDKLiteralMinimumJoin
		Arguments    map[string][32]byte
	}{binding.file, binding.options.TargetTriple, binding.options.Goarch, binding.options.WASMABI, binding.options.X87Mode,
		binding.options.AnnotateSource, binding.options.Sigs, binding.options.X86TailGroups, binding.symbols, binding.reads, binding.literalAccesses, binding.literalMinimum, arguments})
	return sha256.Sum256(data), err
}

func (binding *GoX86NumericalReadBinding) verify() error {
	if binding == nil || binding.source == nil || binding.source != binding.originalSource {
		return numericalSBContext("missing live factory binding")
	}
	fail := func(err error) error {
		binding.source.mu.Lock()
		binding.source.ready = false
		binding.source.mu.Unlock()
		return err
	}
	if binding.originalBinding != binding {
		return fail(numericalSBContext("copied or foreign numerical binding is not the original factory token"))
	}
	if err := rejectMixedNativeAuthorities(binding, binding.options.ARM64ByteCarrierSource); err != nil {
		return err
	}
	if binding.context == nil || reflect.TypeOf(binding.context) != reflect.TypeOf(binding.originalContext) ||
		!reflect.TypeOf(binding.context).Comparable() || binding.context != binding.originalContext {
		return fail(numericalSBContext("binding live context identity changed"))
	}
	if binding.packageInput.Types == nil || binding.packageInput.Types != binding.originalTypes ||
		binding.packageInput.SourceSelection != nil || !numericalSameImports(binding.packageInput.Imports, binding.originalImports) {
		return fail(numericalSBContext("binding private declaration/import identity changed"))
	}
	if err := binding.source.Verify(binding.context); err != nil {
		return err
	}
	if binding.literalMinimum != nil {
		if err := binding.literalMinimum.verify(binding.context, binding.source); err != nil {
			return fail(err)
		}
	}
	sum, err := binding.digest()
	if err != nil || sum != binding.seal || !numericalSameCapabilities(binding.options.Sigs, binding.capabilities) {
		return fail(numericalSBContext("private binding shape changed"))
	}
	for _, sig := range binding.options.Sigs {
		if entry := sig.amd64GoArguments; entry != nil {
			matches := 0
			for _, fn := range binding.source.file.Funcs {
				if fn.Sym == entry.symbol && entry.valid(fn, sig, binding.options.Goarch) {
					matches++
				}
			}
			if matches != 1 {
				return fail(amd64GoArgumentContext("binding lost its unique live original typed argument entry"))
			}
		}
	}
	declarationContext, stop, err := binding.source.numericalDeclarationContext(binding.context)
	if err != nil {
		return fail(err)
	}
	defer stop()
	binding.source.mu.Lock()
	declarations, err := binding.source.numericalDeclarations(declarationContext, binding.packageInput, binding.options.Goarch)
	if err == nil {
		err = numericalDeclarationSyntax(binding.source, binding.packageInput)
	}
	valid := binding.source.ready && reflect.DeepEqual(binding.declarations, declarations) && reflect.DeepEqual(binding.reads, binding.source.readFacts())
	binding.source.mu.Unlock()
	if err != nil {
		return fail(err)
	}
	if !valid {
		return fail(numericalSBContext("declaration/source/owner read join changed"))
	}
	return binding.source.Verify(binding.context)
}

// Imports are obtained only from the same live, already authenticated owner
// selections. A temporary typecheck guard cannot add new files to the original
// source seal or treat the CPU's assembly namespace as a Go import certificate.
func (source *GoX86NumericalReadSource) numericalDeclarations(ctx context.Context, pkg GoPackage, arch string) (map[string]goAMD64FrameDeclaration, error) {
	// This is only an independent declaration query. Do not copy the mutex,
	// ready generation, artifact owner, Frame token or private factory fields.
	guard := &GoAMD64FrameSource{request: source.guard.request, selection: source.guard.selection,
		env: source.guard.env, inputs: make(map[string][32]byte), imports: make(map[string]goAMD64FrameSelection)}
	if source.role == numericalSBSDKSource {
		for path, dependency := range source.guard.imports {
			guard.imports[path] = dependency
		}
	}
	for _, owner := range source.originalOwners {
		if source.sdkAssemblyJoin() != nil {
			// Joined SDK capture accepts only independent SDK CPU owners.
			// Its complete declaration graph is the separately sealed SDK graph;
			// owner callbacks run before/after, never under source.mu here.
			continue
		}
		report, err := owner.observation.Readback(ctx)
		if err != nil {
			return nil, numericalStorageFailure(ctx, "declaration owner readback", err)
		}
		if report.Protocol == gostaticstorage.SDKCPUProtocol || report.Protocol == gostaticstorage.SDKGlobalsProtocol {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
		for decoder.More() {
			var dependency goAMD64FrameSelection
			if err := decoder.Decode(&dependency); err != nil {
				return nil, err
			}
			if dependency.Export != "" {
				guard.imports[dependency.ImportPath] = dependency
			}
		}
	}
	var entries map[string]numericalSourceDeclaration
	var terminals map[string]numericalSourceDeclaration
	var localEntries map[string]bool
	foreignEntry := false
	if source.role == numericalSBSDKSource {
		names, err := numericalGoDeclarationLinknames(pkg.Syntax, pkg.Types)
		if err != nil {
			return nil, err
		}
		entries, terminals, err = numericalTypedSourceDeclarations(source.file, pkg.Path, arch, source.role, names, source.native.CompilerAliases)
		if err != nil {
			return nil, err
		}
		localEntries = make(map[string]bool, len(entries))
		for name, declaration := range entries {
			localEntries[declaration.local] = true
			foreignEntry = foreignEntry || name != gosym.PackagePrefix(pkg.Path)+"."+declaration.local
		}
	}
	if source.sdkAssemblyJoin() != nil && (foreignEntry || x86DirectTailSourceNeeded(source.file) || len(source.native.ArgumentRules) != 0) {
		return source.numericalSDKOrdinaryTailDeclarations(ctx, pkg, arch, entries)
	}
	declarations, err := guard.typedNumericalDeclarationsForArchRole(pkg, arch, source.role == numericalSBSDKSource, localEntries)
	if err != nil {
		return nil, err
	}
	ordinary, err := source.numericalSDKOrdinaryTailDeclarations(ctx, pkg, arch, terminals)
	if err != nil {
		return nil, err
	}
	for name, declaration := range ordinary {
		if _, present := declarations[name]; !present {
			declarations[name] = declaration
		}
	}
	return declarations, nil
}

type x86NumericalReadCertificate struct {
	binding     *GoX86NumericalReadBinding
	read        int
	instruction [32]byte
}

func verifyNumericalReadInputs(file *File, options Options) (result error) {
	for _, sig := range options.Sigs {
		if entry := sig.amd64GoArguments; entry != nil && entry.virtual != nil {
			if entry.owner != nil || entry.virtual.entries[sig.Name] != entry || entry.virtual.live() != nil {
				return amd64GoArgumentContext("virtual arguments require their live GoModule call")
			}
			continue
		}
		if entry := sig.amd64GoArguments; entry != nil && (options.NumericalReads == nil || entry.owner != options.NumericalReads) {
			return amd64GoArgumentContext("typed arguments require their complete live source binding")
		}
	}
	if err := rejectMixedNativeAuthorities(options.NumericalReads, options.ARM64ByteCarrierSource); err != nil {
		return err
	}
	binding := options.NumericalReads
	if binding == nil {
		return nil
	}
	defer func() {
		if result != nil && binding.source != nil {
			binding.source.mu.Lock()
			binding.source.ready = false
			binding.source.mu.Unlock()
		}
	}()
	if err := binding.verify(); err != nil {
		return err
	}
	check := func() error {
		if file == nil || options.ResolveSym == nil {
			return numericalSBContext("consumer lost complete source/resolver")
		}
		shape := options
		shape.ResolveSym, shape.NumericalReads = nil, nil
		fingerprint, err := x86CallerSourceFingerprint(file)
		if err != nil || fingerprint != binding.file || !reflect.DeepEqual(shape, binding.options) || !numericalSameCapabilities(options.Sigs, binding.capabilities) {
			return numericalSBContext("consumer original file/declarations/options changed")
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	for symbol, expected := range binding.symbols {
		if options.ResolveSym(symbol) != expected {
			return numericalSBContext("consumer resolver changed exact storage/function identity")
		}
	}
	if err := check(); err != nil {
		return err
	}
	return binding.verify() // Resolver callbacks cannot mutate a live source/owner.
}

func freezeNumericalReadInputs(file *File, options Options) (*File, Options, error) {
	if err := verifyNumericalReadInputs(file, options); err != nil {
		return nil, Options{}, err
	}
	binding := options.NumericalReads
	if binding == nil {
		return file, options, nil
	}
	encoded, err := json.Marshal(file)
	if err != nil {
		return nil, Options{}, err
	}
	var frozen File
	if err := json.Unmarshal(encoded, &frozen); err != nil {
		return nil, Options{}, err
	}
	options = binding.options
	options.Sigs, err = numericalCloneSignatures(binding.options.Sigs)
	if err != nil {
		return nil, Options{}, err
	}
	options.ResolveSym, options.NumericalReads = binding.resolve, binding
	if err := joinNumericalReadCertificates(&frozen, options); err != nil {
		return nil, Options{}, err
	}
	if err := preserveX86DirectTailNumericalGraph(file, &frozen, options); err != nil {
		return nil, Options{}, err
	}
	return &frozen, options, nil
}

// Join only an independently parsed complete sealed source. Reparse intentionally
// drops all private certificates; neither a copied Instr nor its spelling can
// supply the original source/ordinal/native-read identity.
func joinNumericalReadCertificates(file *File, options Options) error {
	binding := options.NumericalReads
	if binding == nil {
		return nil
	}
	fingerprint, err := x86CallerSourceFingerprint(file)
	if err != nil || fingerprint != binding.file {
		return numericalSBContext("numerical certificate join requires the whole sealed source")
	}
	for i, read := range binding.reads {
		matches := 0
		for f := range file.Funcs {
			fn := &file.Funcs[f]
			if binding.resolve(fn.Sym) != read.Function || read.Instruction < 0 || read.Instruction >= len(fn.Instrs) {
				continue
			}
			ins := &fn.Instrs[read.Instruction]
			if !reflect.DeepEqual(*ins, read.Original) || ins.x86NumericalRead != nil {
				return numericalSBContext("original read ordinal/instruction differs")
			}
			digest, err := fixedLocalInstructionDigest(*ins)
			if err != nil {
				return err
			}
			ins.x86NumericalRead = &x86NumericalReadCertificate{binding, i, digest}
			matches++
		}
		if matches != 1 {
			return numericalSBContext("original read has no unique complete source function")
		}
	}
	if err := joinSDKLiteralCertificates(file, binding); err != nil {
		return err
	}
	return verifyNormalizedNumericalReads(file, options)
}

func numericalCertifiedRead(ins Instr, arch string) (numericalSBReadFact, x86NumericalSBReadForm, bool) {
	cert := ins.x86NumericalRead
	if cert == nil || cert.binding == nil || cert.binding.source == nil || cert.binding.source.revoked.Load() || cert.read < 0 || cert.read >= len(cert.binding.reads) || arch != cert.binding.options.Goarch {
		return numericalSBReadFact{}, x86NumericalSBReadForm{}, false
	}
	read := cert.binding.reads[cert.read]
	digest, err := fixedLocalInstructionDigest(ins)
	form, valid := x86NumericalSBReadProperties(ins, arch)
	if err != nil || digest != cert.instruction || !valid || form.operand != read.Operand || form.spec.sourceBytes != read.Width || !numericalOwnerContains(read.Variable, read.Offset, read.Width) {
		return numericalSBReadFact{}, x86NumericalSBReadForm{}, false
	}
	return read, form, true
}

func verifyNormalizedNumericalReads(file *File, options Options) error {
	if options.NumericalReads == nil {
		return nil
	}
	seen := make(map[int]bool)
	for _, fn := range file.Funcs {
		for ordinal, ins := range fn.Instrs {
			if ins.x86NumericalRead == nil {
				continue
			}
			cert := ins.x86NumericalRead
			read, _, valid := numericalCertifiedRead(ins, options.Goarch)
			if !valid || cert.binding != options.NumericalReads || seen[cert.read] || options.ResolveSym(fn.Sym) != read.Function || ordinal != read.Instruction {
				return numericalSBContext("normalized function/ordinal/operand/native read identity changed")
			}
			seen[cert.read] = true
		}
	}
	if len(seen) != len(options.NumericalReads.reads) {
		return numericalSBContext("normalized read inventory changed or storage collides with local data")
	}
	if err := verifyNormalizedSDKLiteralAccesses(file, options); err != nil {
		return err
	}
	if source := options.NumericalReads.source; source.literals != nil {
		return source.literals.verifyFile(file, source.request.PackagePath)
	}
	if len(file.Data)+len(file.Globl) != 0 {
		return numericalSBContext("normalized read inventory changed or storage collides with local data")
	}
	return nil
}

func numericalSameCapabilities(sigs map[string]FuncSig, expected map[string]numericalSignatureCapabilities) bool {
	if len(sigs) != len(expected) {
		return false
	}
	for name, sig := range sigs {
		cap, found := expected[name]
		if !found || sig.x86CallerRegions != cap.caller || sig.x86FixedLocal != cap.local || sig.amd64GoArguments != cap.arguments {
			return false
		}
	}
	return true
}

func finishNumericalReads(file *File, options Options) error {
	if err := verifyNumericalReadInputs(file, options); err != nil {
		return fmt.Errorf("numerical read post-consumption guard: %w", err)
	}
	return nil
}

func verifyGoNumericalReadInputs(binding *GoX86NumericalReadBinding, pkg GoPackage, opt GoModuleOptions) (result error) {
	if err := rejectMixedNativeAuthorities(binding, opt.ARM64ByteCarrierSource); err != nil {
		return err
	}
	defer func() {
		if result != nil && binding != nil && binding.source != nil {
			binding.source.mu.Lock()
			binding.source.ready = false
			binding.source.mu.Unlock()
		}
	}()
	if err := binding.verify(); err != nil {
		return err
	}
	if pkg.Path != binding.packageInput.Path || pkg.Types != binding.originalTypes || pkg.SourceSelection != nil ||
		!numericalSameImports(pkg.Imports, binding.originalImports) ||
		opt.GOOS+"/"+opt.GOARCH != binding.source.request.Target || opt.GOARCH != binding.options.Goarch || opt.TargetTriple != binding.options.TargetTriple ||
		opt.WASMABI != binding.options.WASMABI || opt.X87Mode != binding.options.X87Mode || opt.AnnotateSource != binding.options.AnnotateSource ||
		opt.Sizes != nil || opt.FrameSizes != nil ||
		opt.ResolveSym == nil || opt.KeepFunc != nil || opt.ManualSig != nil || len(opt.ARM64ClosureABIs) != 0 ||
		opt.FileName != binding.source.request.AssemblyFile && opt.FileName != filepath.Join(binding.source.request.Directory, binding.source.request.AssemblyFile) {
		return numericalSBContext("Go wrapper declaration/profile/source role differs")
	}
	binding.source.mu.Lock()
	err := numericalDeclarationSyntax(binding.source, pkg)
	binding.source.mu.Unlock()
	if err != nil {
		return err
	}
	for symbol, expected := range binding.symbols {
		if opt.ResolveSym(symbol) != expected {
			return numericalSBContext("Go wrapper resolver changed exact source/storage identity")
		}
	}
	return binding.verify()
}

func numericalGoSignatures(binding *GoX86NumericalReadBinding, supplied map[string]FuncSig) (map[string]FuncSig, error) {
	if len(supplied) != len(binding.options.Sigs) {
		return nil, numericalSBContext("Go wrapper signature inventory differs from sealed declarations")
	}
	for name, signature := range supplied {
		original, found := binding.options.Sigs[name]
		if !found || !reflect.DeepEqual(numericalSignatureShape(signature), numericalSignatureShape(original)) {
			return nil, numericalSBContext("Go wrapper signature differs from sealed original declaration")
		}
	}
	// Only the opaque factory transports separately verified private contracts;
	// a ManualSig callback or a new source selection cannot recreate them.
	return numericalCloneSignatures(binding.options.Sigs)
}

// Original caller bytes and sealed CPP are different roles. Only this exact
// selected raw source may consume the already independently assembled CPP;
// equal parsed instructions cannot substitute another source or header set.
func numericalGoAssemblyInput(binding *GoX86NumericalReadBinding, input []byte) (string, error) {
	if binding == nil || binding.source == nil || binding.originalBinding != binding {
		return "", numericalSBContext("Go wrapper has no original numerical source token")
	}
	source := binding.source
	source.mu.Lock()
	defer source.mu.Unlock()
	name := filepath.Join(source.request.Directory, source.request.AssemblyFile)
	original, retained := source.native.Sources[name]
	expected, selected := source.guard.inputs[name]
	if !source.ready || source.revoked.Load() || source.identity != source || !retained || !selected ||
		sha256.Sum256(original) != expected || !bytes.Equal(input, original) {
		source.ready = false
		return "", numericalSBContext("Go wrapper original selected ASM bytes changed")
	}
	return source.cpp.Output, nil
}
