package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/xgo-dev/llvm"
)

// GoPackage provides the Go declarations and syntax needed to bind a Plan 9
// asm file to real Go symbols.
type GoPackage struct {
	Path    string
	Types   *types.Package
	Imports map[string]*types.Package
	Syntax  []*ast.File
	// ImportSyntax is the complete selected declaration syntax for entries in
	// Imports, from the same load/profile as their actual types.Package values.
	// It supplies only ordinary numerical global-read declarations, never
	// caller, native-entry, pointer, writable storage or captured SDK authority.
	ImportSyntax map[string][]*ast.File

	// SourceSelection is the compiler's complete same-profile typed selection.
	// Nil keeps the existing conservative raw-return pointer contract. Supplying
	// source data does not itself certify a stack, memory effect or continuation.
	SourceSelection *GoSourceSelection
}

// GoModuleOptions configures TranslateGoModule.
//
// GOARCH is required and currently accepts only "amd64", "386", and "arm64".
// If ResolveSym is nil, the default resolver only strips ABI suffixes.
type GoModuleOptions struct {
	FileName string
	GOOS     string
	GOARCH   string
	// SourcePreprocessed means src is the complete output of the caller's
	// selected package/target preprocessor, including its generated headers.
	// Do not expand generated identifiers or apply ambient Go feature macros
	// again. This supplies no source or native authority and cannot accompany
	// NumericalReads, X86TLSMoves or ARM64ByteCarrierSource bindings, which
	// retain their own complete original-source preprocessing contracts.
	SourcePreprocessed bool
	// Sizes is the type layout used to type-check the package. When nil,
	// TranslateGoModule uses the standard gc layout for GOARCH. Callers with a
	// custom data model, such as Emscripten wasm32 versus Memory64, must pass
	// the same Sizes instance used by go/types.
	Sizes types.Sizes
	// FrameSizes describes the stack-frame layout encoded in FP offsets. It
	// defaults to Sizes. This is separate because LLGo's C-compatible wasm32
	// mode uses 32-bit values while translating assembly emitted for Go's
	// 64-bit GOARCH=wasm frame layout.
	FrameSizes     types.Sizes
	TargetTriple   string
	WASMABI        WASMABI
	X87Mode        X87Mode
	AnnotateSource bool
	NumericalReads *GoX86NumericalReadBinding
	X86TLSMoves    *GoX86TLSMoveBinding

	// ARM64ByteCarrierSource retains the original bounded capture lease.
	// LLVM Context controls resources, not cancellation or native authority.
	ARM64ByteCarrierSource *GoARM64ByteCarrierSource

	ResolveSym func(sym string) string
	KeepFunc   func(textSym, resolved string) bool
	ManualSig  func(resolved string) (FuncSig, bool)

	// ARM64ClosureABIs supplies producer-proven hidden carriers after binding
	// actual Go declarations. It neither invents Go args nor infers R26 input.
	ARM64ClosureABIs map[string]ARM64ClosureABI
}

// GoFunction records the original TEXT symbol and its resolved LLVM symbol.
type GoFunction struct {
	TextSymbol     string
	ResolvedSymbol string
}

// GoModuleTranslation is the result of TranslateGoModule.
//
// Callers own Module and must call Module.Dispose when finished with it.
type GoModuleTranslation struct {
	Module     llvm.Module
	Signatures map[string]FuncSig
	Functions  []GoFunction
}

// TranslateGoModule binds Go declarations to a Plan 9 asm file and translates
// the result into an LLVM module in one call.
//
// The package must provide go/types information for the declarations referenced
// by the assembly. Methods and variadic functions are not supported.
func TranslateGoModule(pkg GoPackage, src []byte, opt GoModuleOptions) (*GoModuleTranslation, error) {
	return translateGoModuleInContext(llvm.GlobalContext(), pkg, src, opt)
}

// TranslateGoModuleInContext binds and translates the complete Go assembly
// source in the supplied LLVM context. The caller retains context ownership,
// including on error, and must dispose a successful module before its context.
func TranslateGoModuleInContext(ctx llvm.Context, pkg GoPackage, src []byte, opt GoModuleOptions) (*GoModuleTranslation, error) {
	return translateGoModuleInContext(ctx, pkg, src, opt)
}

// Internal high-volume callers can own the context without changing the public
// binding contract. Dispose the returned module before disposing ctx.
func translateGoModuleInContext(ctx llvm.Context, pkg GoPackage, src []byte, opt GoModuleOptions) (result *GoModuleTranslation, resultErr error) {
	if opt.SourcePreprocessed && (opt.NumericalReads != nil || opt.X86TLSMoves != nil || opt.ARM64ByteCarrierSource != nil) {
		return nil, fmt.Errorf("%w: preprocessed Go assembly cannot replace a captured source authority", ErrProbeNeedsContext)
	}
	if err := rejectMixedNativeAuthorities(opt.NumericalReads, opt.ARM64ByteCarrierSource); err != nil {
		return nil, err
	}
	if source := opt.ARM64ByteCarrierSource; source != nil {
		var callbackFailure error
		if err := source.Verify(source.lease); err != nil {
			return nil, err
		}
		original, err := arm64ByteCarrierGoView(source, pkg)
		if err != nil {
			source.revokeCarrier()
			return nil, err
		}
		defer func() {
			final := finishARM64ByteCarrierGoSource(source, pkg, original, result)
			if resultErr != nil || callbackFailure != nil || final != nil {
				source.revokeCarrier()
				if result != nil && !result.Module.IsNil() {
					result.Module.Dispose()
				}
				result, resultErr = nil, errors.Join(resultErr, callbackFailure, final)
			}
		}()
		goos, _, _ := strings.Cut(source.request.Target, "/")
		if opt.GOOS != goos || opt.ManualSig != nil || len(opt.ARM64ClosureABIs) != 0 {
			return nil, arm64ByteCarrierContext("Go profile/custom declaration/closure mapping differs from the closed source")
		}
		// Go binding calls user resolvers before reaching the LLVM consumer.
		// Retain the original capture owner through every such callback; a
		// failed callback must not be followed by another invocation or output.
		live := func() bool {
			if callbackFailure == nil {
				callbackFailure = source.liveCarrier()
			}
			return callbackFailure == nil
		}
		resolve := opt.ResolveSym
		if resolve == nil {
			resolve = goStripABISuffix
		}
		opt.ResolveSym = func(symbol string) string {
			if !live() {
				return ""
			}
			resolved := resolve(symbol)
			if !live() {
				return ""
			}
			return resolved
		}
		if keep := opt.KeepFunc; keep != nil {
			opt.KeepFunc = func(symbol, resolved string) bool {
				if !live() {
					return false
				}
				retained := keep(symbol, resolved)
				return live() && retained
			}
		}
	}
	originalSource := src
	originalSourceDigest := sha256.Sum256(src)
	if binding := opt.X86TLSMoves; binding != nil {
		var err error
		src, err = tlsGoAssemblyInput(binding, pkg, src, opt)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := finishTLSGoInput(binding, pkg, originalSource, originalSourceDigest, opt); err != nil {
				if result != nil && !result.Module.IsNil() {
					result.Module.Dispose()
				}
				result, resultErr = nil, errors.Join(resultErr, err)
			}
		}()
	}
	if binding := opt.NumericalReads; binding != nil {
		if err := verifyGoNumericalReadInputs(binding, pkg, opt); err != nil {
			return nil, err
		}
		expanded, err := numericalGoAssemblyInput(binding, src)
		if err != nil {
			return nil, err
		}
		src = []byte(expanded)
		defer func() {
			err := verifyGoNumericalReadInputs(binding, pkg, opt)
			if _, sourceErr := numericalGoAssemblyInput(binding, originalSource); sourceErr != nil {
				err = errors.Join(err, sourceErr)
			}
			if sha256.Sum256(originalSource) != originalSourceDigest {
				err = errors.Join(err, numericalSBContext("Go wrapper source bytes changed during consumption"))
				binding.source.mu.Lock()
				binding.source.ready = false
				binding.source.mu.Unlock()
			}
			if err != nil {
				if result != nil && !result.Module.IsNil() {
					result.Module.Dispose()
				}
				result = nil
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}
	pkgPath := pkg.Path
	if pkgPath == "" && pkg.Types != nil {
		pkgPath = pkg.Types.Path()
	}
	if pkgPath == "" {
		return nil, fmt.Errorf("empty package path")
	}
	if pkg.Types == nil || pkg.Types.Scope() == nil {
		return nil, fmt.Errorf("%s: missing types (needed for asm signatures)", pkgPath)
	}
	if opt.GOARCH == "" {
		return nil, fmt.Errorf("%s: empty GOARCH", pkgPath)
	}
	asmName := opt.FileName
	if asmName == "" {
		asmName = "<asm>"
	}

	arch, err := goArchFor(opt.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pkgPath, err)
	}
	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(sym string) string { return goStripABISuffix(sym) }
	}

	var file *File
	if opt.SourcePreprocessed {
		file, err = parsePreprocessedAssembly(arch, string(src))
	} else {
		if opt.NumericalReads == nil && opt.X86TLSMoves == nil {
			src = ExpandGoAssemblySource(pkg, src, opt.GOARCH)
		}
		file, err = ParseWithDefines(arch, string(src), GoAssemblerDefines(opt.GOOS, opt.GOARCH))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: parse %s: %w", pkgPath, asmName, err)
	}
	virtualPackage := pkg
	virtualPackage.Path = pkgPath
	virtualArguments, err := bindAMD64GoVirtualArguments(virtualPackage, file, originalSource, originalSourceDigest, opt, resolve)
	if err != nil {
		return nil, err
	}
	if virtualArguments != nil {
		resolve = virtualArguments.resolveSymbol
		defer func() {
			final := virtualArguments.verify()
			virtualArguments.close()
			if final != nil {
				if result != nil && !result.Module.IsNil() {
					result.Module.Dispose()
				}
				result, resultErr = nil, errors.Join(resultErr, final)
			}
		}()
	}
	var readOnlyStorage *goReadOnlyStorage
	if opt.NumericalReads == nil && opt.X86TLSMoves == nil && opt.ARM64ByteCarrierSource == nil {
		storagePackage := pkg
		storagePackage.Path = pkgPath
		readOnlyStorage, err = bindGoReadOnlyStorage(storagePackage, file, opt.Sizes, opt.GOARCH, resolve)
		if err != nil {
			return nil, err
		}
		if readOnlyStorage != nil {
			resolve = readOnlyStorage.resolveSymbol
			defer func() {
				final := readOnlyStorage.verify()
				if sha256.Sum256(originalSource) != originalSourceDigest {
					final = errors.Join(final, goReadOnlyContext("original Go assembly input changed during consumption"))
				}
				if final != nil {
					if result != nil && !result.Module.IsNil() {
						result.Module.Dispose()
					}
					result, resultErr = nil, errors.Join(resultErr, final)
				}
			}()
		}
	}
	closureSource := *file
	closureSource.Funcs = append([]Func(nil), file.Funcs...)
	tailSigs, err := goBindARM64ABI0TailDeclarations(pkg, file, resolve, opt)
	if err != nil {
		return nil, err
	}
	file, err = PrepareGoARM64ABI0TailContinuations(file, tailSigs, resolve)
	if err != nil {
		return nil, fmt.Errorf("%s: private source contract %s: %w", pkgPath, asmName, err)
	}
	var virtualSignatures map[string]FuncSig
	if virtualArguments != nil {
		virtualSignatures, err = goSigsForAsmFile(pkg, file, resolve, opt.GOARCH, opt.Sizes, opt.FrameSizes, opt.ManualSig)
		if err != nil {
			return nil, err
		}
		if err := virtualArguments.attach(virtualSignatures); err != nil {
			return nil, err
		}
	}
	var registerBoolCalls *x86ABI0BoolCallSource
	if (opt.GOARCH == "amd64" || opt.GOARCH == "386") &&
		(x86DirectTailSourceNeeded(file) || len(goFixedLocalLeafSymbols(file, resolve, opt.ManualSig)) != 0) {
		completeSigs, err := goSigsForAsmFile(pkg, file, resolve, opt.GOARCH, opt.Sizes, opt.FrameSizes, opt.ManualSig)
		if err != nil {
			return nil, err
		}
		if err := virtualArguments.attach(completeSigs); err != nil {
			return nil, err
		}
		if binding := opt.NumericalReads; binding != nil {
			// The complete graph consumes the same independently bound private
			// identities as lowering, not just fresh language signature shapes.
			completeSigs, err = numericalGoSignatures(binding, completeSigs)
			if err != nil {
				return nil, err
			}
		}
		request := Options{Goarch: opt.GOARCH, TargetTriple: opt.TargetTriple,
			ResolveSym: resolve, Sigs: completeSigs, NumericalReads: opt.NumericalReads, X86TLSMoves: opt.X86TLSMoves,
			WASMABI: opt.WASMABI, X87Mode: opt.X87Mode, AnnotateSource: opt.AnnotateSource, goReadOnlyStorage: readOnlyStorage}
		calls, err := prepareX86ABI0BoolCalls(file, request)
		if err != nil {
			return nil, err
		}
		if calls != nil && calls.customGraph != nil {
			registerBoolCalls = calls // One original graph and one shared flow budget.
			request.x86BoolCallSource = calls
		}
		file, err = PrepareX86DirectTailSource(file, request)
		if err != nil {
			return nil, err
		}
	}
	if err := virtualArguments.audit(file, virtualSignatures, opt, resolve, readOnlyStorage); err != nil {
		return nil, err
	}
	completeFile := file
	potentialBoolCalls := x86ABI0BoolCallsNeeded(completeFile, opt.GOARCH)
	boolCallSource := false
	if file.x86DirectTails != nil || potentialBoolCalls || virtualArguments != nil {
		filtered := *file
		file = &filtered // KeepFunc cannot crop the complete graph origin/signatures.
	}
	if opt.KeepFunc != nil {
		keep := make([]Func, 0, len(file.Funcs))
		for _, fn := range file.Funcs {
			resolved := resolve(goTextSymbolForResolution(fn.Sym))
			if opt.KeepFunc(fn.Sym, resolved) {
				keep = append(keep, fn)
			}
		}
		file.Funcs = keep
	}

	signatureFile := file
	if file.x86DirectTails != nil || registerBoolCalls != nil || virtualArguments != nil {
		signatureFile = completeFile // Recheck every root after caller callbacks.
	}
	sigs, err := goSigsForAsmFile(pkg, signatureFile, resolve, opt.GOARCH, opt.Sizes, opt.FrameSizes, opt.ManualSig)
	if err != nil {
		return nil, fmt.Errorf("%s: sigs %s: %w", pkgPath, asmName, err)
	}
	if potentialBoolCalls {
		for _, fn := range file.Funcs {
			if !x86ABI0BoolFunctionControlNeeded(fn) {
				continue
			}
			if sig, declared := sigs[resolve(goTextSymbolForResolution(fn.Sym))]; declared && sig.Ret == I1 {
				// Actual selected I1 CALLs/terminals require complete original types;
				// unrelated nonbool/unused TEXTs need no new declaration query.
				// With no dropped function, this first signature inventory is
				// already complete. No temporary callee proof is built here.
				if len(file.Funcs) != len(completeFile.Funcs) && signatureFile != completeFile {
					sigs, err = goSigsForAsmFile(pkg, completeFile, resolve, opt.GOARCH, opt.Sizes, opt.FrameSizes, opt.ManualSig)
					if err != nil {
						return nil, err
					}
				}
				boolCallSource = true
				break
			}
		}
	}
	if binding := opt.NumericalReads; binding != nil {
		sigs, err = numericalGoSignatures(binding, sigs)
		if err != nil {
			return nil, err
		}
	}
	if err := virtualArguments.attach(sigs); err != nil {
		return nil, err
	}
	if graph := file.x86DirectTails; graph != nil {
		request, signatures := file, sigs
		defer func() {
			final := graph.verify(request, Options{Goarch: opt.GOARCH, TargetTriple: opt.TargetTriple, ResolveSym: resolve, Sigs: signatures,
				NumericalReads: opt.NumericalReads, WASMABI: opt.WASMABI, X87Mode: opt.X87Mode, AnnotateSource: opt.AnnotateSource, goReadOnlyStorage: readOnlyStorage})
			if sha256.Sum256(originalSource) != originalSourceDigest {
				final = errors.Join(final, x86DirectTailContext("original Go assembly input changed during consumption"))
			}
			if final != nil {
				if result != nil && !result.Module.IsNil() {
					result.Module.Dispose()
				}
				result = nil
				resultErr = errors.Join(resultErr, final)
			}
		}()
	}
	for name, sourceSig := range tailSigs {
		if sourceSig.arm64ABI0TailDeclaration != nil {
			sig, present := sigs[name]
			if !present {
				continue // Whole-file audit ran before dropping this unused root.
			}
			if !reflect.DeepEqual(arm64ABI0SignatureSnapshot(sig), arm64ABI0SignatureSnapshot(sourceSig)) {
				return nil, arm64GoABIContext("ABI0 tail changed its declaration during signature inference")
			}
			sigs[name] = sourceSig
		}
	}
	if err := bindGoARM64ClosureABIs(pkg, &closureSource, sigs, opt, resolve); err != nil {
		return nil, err
	}
	var boolCalls *x86ABI0BoolCallSource
	var callOriginal *File
	if boolCallSource || registerBoolCalls != nil {
		callOriginal = completeFile
		boolCalls = registerBoolCalls
		if boolCalls == nil {
			boolCalls, err = prepareX86ABI0BoolCalls(completeFile, Options{Goarch: opt.GOARCH, TargetTriple: opt.TargetTriple, ResolveSym: resolve, Sigs: sigs, goReadOnlyStorage: readOnlyStorage})
			if err != nil {
				return nil, err
			}
		}
		if boolCalls != nil {
			defer func() {
				final := boolCalls.verify()
				if sha256.Sum256(originalSource) != originalSourceDigest {
					final = errors.Join(final, x86ABI0BoolCallContext("original Go input changed during complete call consumption"))
				}
				if final != nil {
					if result != nil && !result.Module.IsNil() {
						result.Module.Dispose()
					}
					result = nil
					resultErr = errors.Join(resultErr, final)
				}
			}()
		}
	}
	mod, err := TranslateModuleInContext(ctx, file, Options{
		goReadOnlyStorage:      readOnlyStorage,
		x86OriginalFile:        callOriginal,
		x86BoolCallSource:      boolCalls,
		TargetTriple:           opt.TargetTriple,
		ResolveSym:             resolve,
		Sigs:                   sigs,
		Goarch:                 opt.GOARCH,
		WASMABI:                opt.WASMABI,
		X87Mode:                opt.X87Mode,
		AnnotateSource:         opt.AnnotateSource,
		NumericalReads:         opt.NumericalReads,
		X86TLSMoves:            opt.X86TLSMoves,
		ARM64ByteCarrierSource: opt.ARM64ByteCarrierSource,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: translate %s: %w", pkgPath, asmName, err)
	}

	funcs := make([]GoFunction, 0, len(file.Funcs))
	metadataResolve := resolve
	if opt.NumericalReads != nil {
		metadataResolve = opt.NumericalReads.resolve
	}
	for _, fn := range file.Funcs {
		if file.x86DirectTailHelper(fn.Sym) {
			continue // The private node is not a Go/LLVM entry or callable ABI.
		}
		funcs = append(funcs, GoFunction{TextSymbol: fn.Sym, ResolvedSymbol: metadataResolve(goTextSymbolForResolution(fn.Sym))})
	}

	return &GoModuleTranslation{Module: mod, Signatures: sigs, Functions: funcs}, nil
}

func bindGoARM64ClosureABIs(pkg GoPackage, original *File, sigs map[string]FuncSig, opt GoModuleOptions, resolve func(string) string) error {
	if len(opt.ARM64ClosureABIs) == 0 {
		return nil
	}
	linknames := goLinknameRemoteToLocal(pkg.Syntax)
	pkgPath := pkg.Path
	if pkgPath == "" {
		pkgPath = pkg.Types.Path()
	}
	for name, abi := range opt.ARM64ClosureABIs {
		sig, ok := sigs[name]
		if !ok {
			return arm64GoABIContext("closure carrier %q has no declaration-bound assembly signature", name)
		}
		var declaration *types.Func
		for _, fn := range original.Funcs {
			if resolve(goTextSymbolForResolution(fn.Sym)) != name {
				continue
			}
			if !strings.HasSuffix(fn.Sym, "<ABIInternal>") {
				return arm64GoABIContext("closure entry %q needs its actual source ABIInternal identity", name)
			}
			declName := strings.TrimPrefix(name, pkgPath+".")
			if declName == name {
				var err error
				declName, err = goDeclNameForSymbol(goStripABISuffix(fn.Sym), linknames)
				if err != nil {
					return arm64GoABIContext("closure entry %q has no source Go declaration: %v", name, err)
				}
			}
			declaration, _ = pkg.Types.Scope().Lookup(declName).(*types.Func)
		}
		if _, err := DeriveARM64GoRegisterABI(declaration, sig); err != nil {
			return err
		}
		carrier := abi
		sig.ARM64ClosureABI = &carrier
		sigs[name] = sig
	}
	// KeepFunc may omit a sibling, but it may not hide the original entry's
	// address or an ordinary direct call which never supplied a carrier.
	return validateARM64ClosureFile(original, Options{
		Goarch: opt.GOARCH, TargetTriple: opt.TargetTriple, Sigs: sigs,
	}, resolve)
}

// ExpandGoAssemblySource resolves the constants and type-layout identifiers
// that cmd/compile writes to a package's generated go_asm.h. Callers that parse
// package assembly themselves must run this before Parse; leaving a $const_X
// token unresolved can otherwise be mistaken for a successfully translated
// zero value or rejected only after unrelated lowering has begun.
func ExpandGoAssemblySource(pkg GoPackage, src []byte, goarch string) []byte {
	if bytes.Contains(src, []byte("const_")) {
		src = goExpandConsts(src, pkg.Types, pkg.Imports)
	}
	// Struct layout macros only exist when the assembly includes go_asm.h.
	// Keep the common path cheap: building them walks every package-scope type.
	if bytes.Contains(src, []byte("go_asm.h")) {
		src = goExpandAsmHeaderTypes(src, pkg.Types, goarch)
	}
	return src
}

var goABISuffixRe = regexp.MustCompile(`<ABI[^>]*>$`)
var goConstRefRe = regexp.MustCompile(`\bconst_[A-Za-z0-9_]+\b`)
var goConstPlusRefRe = regexp.MustCompile(`([\pL\pN_∕·./]+)\+const_([A-Za-z0-9_]+)`)
var goAsmHeaderIdentRe = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)

func goStripABISuffix(sym string) string {
	sym = goABISuffixRe.ReplaceAllString(sym, "")
	return strings.TrimSuffix(sym, "<>")
}

func goTextSymbolForResolution(sym string) string {
	return goABISuffixRe.ReplaceAllString(sym, "")
}

func goArchFor(goarch string) (Arch, error) {
	switch goarch {
	case "amd64", "386":
		return ArchAMD64, nil
	case "arm":
		return ArchARM, nil
	case "arm64":
		return ArchARM64, nil
	case "wasm":
		return ArchWASM, nil
	default:
		return "", fmt.Errorf("Plan 9 asm unsupported arch %q", goarch)
	}
}

func goSigsForAsmFile(pkg GoPackage, file *File, resolve func(sym string) string, goarch string, sz, frameSz types.Sizes, manualSig func(string) (FuncSig, bool)) (map[string]FuncSig, error) {
	if sz == nil {
		sz = types.SizesFor("gc", goarch)
	}
	if sz == nil {
		return nil, fmt.Errorf("missing sizes for goarch %q", goarch)
	}
	if frameSz == nil {
		frameSz = sz
	}
	b := goSigBuilder{
		sigs:       make(map[string]FuncSig, len(file.Funcs)),
		localSigs:  make(map[string]bool),
		scope:      pkg.Types.Scope(),
		sz:         sz,
		frameSz:    frameSz,
		linknames:  goLinknameRemoteToLocal(pkg.Syntax),
		pkgPath:    pkg.Path,
		resolve:    resolve,
		goarch:     goarch,
		manualSig:  manualSig,
		directTail: (goarch == "amd64" || goarch == "386") && x86DirectTailSourceNeeded(file),
	}
	if goarch == "amd64" {
		b.fixedLocalLeaves = goFixedLocalLeafSymbols(file, resolve, manualSig)
		b.directTail = b.directTail || len(b.fixedLocalLeaves) != 0
	}
	if b.pkgPath == "" {
		b.pkgPath = pkg.Types.Path()
	}
	if err := b.addDeclaredFuncSigs(file); err != nil {
		return nil, err
	}
	b.addCustomBoolHelperTransports(file)
	if err := b.addReferencedFuncSigs(file); err != nil {
		return nil, err
	}
	if goarch == "wasm" {
		for _, fn := range file.Funcs {
			resolved := resolve(goTextSymbolForResolution(fn.Sym))
			fs := b.sigs[resolved]
			if native, ok := wasmGoNativeFuncSig(resolved); ok {
				fs = native
			} else if b.localSigs[resolved] {
				if wasmUsesNativeReturn(fn) {
					var err error
					fs, err = InferWASMAssemblyFuncSig(fn, resolved)
					if err != nil {
						return nil, err
					}
					fs.WASMNative = true
				} else {
					fs = FuncSig{Name: resolved, Ret: Void}
				}
			}
			if wasmNeedsIncomingContext(fn) {
				fs.WASMContext = Ptr
			}
			b.sigs[resolved] = fs
		}
	}
	// A file-local symbol does not imply a zero-argument C or Go signature.
	// Keep signatures obtained from declarations, supported tail-call inference,
	// or ManualSig; raw register entry points require the native backend.
	for resolved := range b.localSigs {
		if _, ok := b.sigs[resolved]; !ok {
			if b.directTail {
				continue // The whole-source graph must close this non-callable node.
			}
			if goarch == "arm64" {
				return nil, arm64GoABIContext("missing signature for file-local assembly %q; supply an explicit entry or closed source continuation contract", resolved)
			}
			return nil, fmt.Errorf("missing signature for file-local assembly %q; supply ManualSig or use the native backend", resolved)
		}
	}
	if pkg.SourceSelection != nil && GoX86RawReturnCallerBindingNeeded(file, goarch, resolve, b.sigs) {
		if !x86CallerTargetSizesValid(sz) {
			return nil, fmt.Errorf("%w: bounded raw-return callers need the actual AMD64 numerical/pointer data layout", ErrProbeNeedsContext)
		}
		return BindGoX86RawReturnCallerRegions(pkg, file, goarch, resolve, b.sigs)
	}
	return b.sigs, nil
}

// Observe explicit custom transports only for an actual ordinary I1 root.
// This does not make a private node callable or give it the caller's frame:
// the complete register-tail graph must independently prove its result writes.
func (b *goSigBuilder) addCustomBoolHelperTransports(file *File) {
	if b.goarch != "386" || !b.directTail || b.manualSig == nil {
		return
	}
	needed := false
	for _, fn := range file.Funcs {
		if !strings.HasSuffix(fn.Sym, "<>") && x86DirectTailRootNeeded(fn) {
			sig, declared := b.sigs[b.resolve(goTextSymbolForResolution(fn.Sym))]
			needed = needed || declared && x86ABI0BoolDeclarationRole(sig, b.goarch)
		}
	}
	if !needed {
		return
	}
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") {
			name := b.resolve(goTextSymbolForResolution(fn.Sym))
			if sig, supplied := goLookupManualSig(b.manualSig, name); supplied {
				b.sigs[name] = sig
			}
		}
	}
}

func wasmUsesNativeReturn(fn Func) bool {
	for _, ins := range fn.Instrs {
		if normalizeInstructionOpcode(ins.Op) == "WASMRETURN" {
			return true
		}
	}
	return false
}

// WASMAssemblyUsesNativeReturn reports whether fn contains Go's WebAssembly
// Return pseudo-instruction. Unlike RET, Return exchanges a result through the
// native wasm operand stack and therefore requires a native wasm signature.
func WASMAssemblyUsesNativeReturn(fn Func) bool {
	return wasmUsesNativeReturn(fn)
}

type goSigBuilder struct {
	sigs             map[string]FuncSig
	localSigs        map[string]bool
	scope            *types.Scope
	sz               types.Sizes
	frameSz          types.Sizes
	linknames        map[string]string
	pkgPath          string
	resolve          func(sym string) string
	goarch           string
	manualSig        func(string) (FuncSig, bool)
	directTail       bool            // source-cost detection only; the graph must prove every node
	fixedLocalLeaves map[string]bool // Observed non-callable source roles, not helper signatures.
}

func (b *goSigBuilder) addDeclaredFuncSigs(file *File) error {
	for i := range file.Funcs {
		textSym := file.Funcs[i].Sym
		sym := goStripABISuffix(textSym)
		resolved := b.resolve(goTextSymbolForResolution(textSym))
		if b.directTail && (strings.HasSuffix(textSym, "<>") || b.fixedLocalLeaves[textSym]) {
			if !b.fixedLocalLeaves[textSym] {
				if sig, found := goLookupManualSig(b.manualSig, resolved); found &&
					x86BoundedVoidABI0Declaration(file.Funcs[i], sig, b.goarch) {
					b.sigs[resolved] = sig
					continue // Keep this real bounded ABI; never invent one for a graph node.
				}
			}
			b.localSigs[resolved] = true
			continue // No ManualSig/zero-arg/caller signature becomes a helper ABI.
		}
		if ms, ok := goLookupManualSig(b.manualSig, resolved); ok {
			b.sigs[resolved] = ms
			continue
		}

		declName := ""
		if strings.HasPrefix(resolved, b.pkgPath+".") {
			declName = strings.TrimPrefix(resolved, b.pkgPath+".")
		} else {
			var err error
			declName, err = goDeclNameForSymbol(sym, b.linknames)
			if err != nil {
				return err
			}
		}
		obj := b.scope.Lookup(declName)
		if obj == nil {
			if strings.HasSuffix(textSym, "<>") || b.goarch == "wasm" {
				if b.localSigs == nil {
					b.localSigs = make(map[string]bool)
				}
				b.localSigs[resolved] = true
				if b.goarch == "arm" {
					if native, ok := ARMKernelHelperFuncSig(file.Funcs[i], resolved); ok {
						b.sigs[resolved] = native
					}
				}
				continue
			}
			return fmt.Errorf("missing Go declaration for asm symbol %q", sym)
		}
		fn, ok := obj.(*types.Func)
		if !ok {
			return fmt.Errorf("asm symbol %q maps to non-func %T", sym, obj)
		}
		fs, err := goFuncSigForDeclaredFunc(resolved, fn, b.goarch, b.sz, b.frameSz, true)
		if err != nil {
			return err
		}
		if b.goarch == "arm64" && strings.HasSuffix(textSym, "<ABIInternal>") {
			fs.ARM64GoRegisterABI, err = DeriveARM64GoRegisterABI(fn, fs)
			if err != nil {
				return err
			}
		}
		b.sigs[resolved] = fs
	}
	return nil
}

func wasmGoNativeFuncSig(name string) (FuncSig, bool) {
	local := strings.HasSuffix(name, "$local")
	base := strings.TrimSuffix(name, "$local")
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		base = base[i+1:]
	}
	native := func(args []LLVMType, ret LLVMType) FuncSig {
		regs := make([]Reg, len(args))
		for i := range regs {
			regs[i] = Reg(fmt.Sprintf("R%d", i))
		}
		return FuncSig{Name: name, Args: args, Ret: ret, ArgRegs: regs, WASMNative: true}
	}
	switch base {
	case "_rt0_wasm_js", "_rt0_wasm_wasip1", "_rt0_wasm_wasip1_lib",
		"wasm_export_resume", "wasm_pc_f_loop", "wasm_export_lib", "notInitialized":
		return native(nil, Void), true
	case "wasm_export_run":
		return native([]LLVMType{I32, I32}, Void), true
	case "wasm_export_getsp":
		return native(nil, I32), true
	case "wasm_pc_f_loop_export":
		return native([]LLVMType{I32}, Void), true
	case "wasmDiv":
		return native([]LLVMType{I64, I64}, I64), true
	case "wasmTruncS", "wasmTruncU":
		return native([]LLVMType{LLVMType("double")}, I64), true
	case "gcWriteBarrier":
		if local {
			// Go 1.21 and newer use a file-local helper that receives the
			// requested buffer size and returns its address on the wasm stack.
			return native([]LLVMType{I64}, I64), true
		}
		// Go 1.20 exposes runtime.gcWriteBarrier as a two-argument native
		// helper. It writes the slot itself and has no wasm result.
		return native([]LLVMType{I64, I64}, Void), true
	case "gcWriteBarrier1", "gcWriteBarrier2", "gcWriteBarrier3", "gcWriteBarrier4",
		"gcWriteBarrier5", "gcWriteBarrier6", "gcWriteBarrier7", "gcWriteBarrier8":
		return native(nil, I64), true
	case "cmpbody":
		return native([]LLVMType{I64, I64, I64, I64}, I64), true
	case "memeqbody":
		return native([]LLVMType{I64, I64, I64}, I64), true
	case "memcmp", "memchr":
		return native([]LLVMType{I32, I32, I32}, I32), true
	}
	return FuncSig{}, false
}

// LookupGoWASMNativeFuncSig returns the native WebAssembly ABI used by Go
// assembly entry points whose signatures are not described by Go declarations.
// These functions are part of the Go runtime/standard-library assembly
// contract and intentionally exchange values through wasm registers or the
// operand stack instead of the ordinary Go stack ABI.
func LookupGoWASMNativeFuncSig(name string) (FuncSig, bool) {
	return wasmGoNativeFuncSig(name)
}

func (b *goSigBuilder) addReferencedFuncSigs(file *File) error {
	for _, fn := range file.Funcs {
		callerResolved := b.resolve(goTextSymbolForResolution(fn.Sym))
		callerSig, hasCallerSig := b.sigs[callerResolved]
		for _, ins := range fn.Instrs {
			base, tailJump, ok := goReferencedFunc(ins)
			if !ok {
				continue
			}
			if b.directTail && (strings.HasSuffix(base, "<>") || b.fixedLocalLeaves[base]) {
				continue // Bound only by complete source nodes and root must-state.
			}
			if err := b.addGoDeclSig(base); err != nil {
				return err
			}
			targetResolved := b.resolve(base)
			if _, ok := b.sigs[targetResolved]; ok {
				continue
			}
			if b.goarch == "wasm" {
				if native, ok := wasmGoNativeFuncSig(targetResolved); ok {
					b.sigs[targetResolved] = native
					continue
				}
			}
			if b.directTail && tailJump {
				return x86DirectTailContext("ordinary external terminal lacks an actual declaration or explicit signature: %s", base)
			}
			if tailJump && hasCallerSig {
				if b.goarch == "arm64" && arm64PrivateTailSymbol(base+"(SB)") {
					return arm64GoABIContext("private tail %q has no declaration or explicit register transport; caller Frame cannot supply it", base)
				}
				// Best-effort fallback for helper<> tail-jumps where the callee is an
				// internal asm label with no Go declaration. Callers can override this
				// via ManualSig when the inferred signature is not identical.
				fs := callerSig
				fs.Name = targetResolved
				fs.x86BorrowedBoolTail = (b.goarch == "386" || b.goarch == "amd64") && fs.Ret == I1
				// A borrowed scalar signature is not a declaration-backed Go
				// register-entry proof for the unresolved helper.
				fs.ARM64GoRegisterABI = nil
				b.sigs[targetResolved] = fs
				continue
			}
			if !tailJump {
				// Keep ordinary unresolved calls untyped so the backend reports the
				// missing declaration instead of silently dropping arguments/results.
				continue
			}
			// A tail target with no known caller signature has no type evidence
			// either. Leave it unresolved; native register entry points must not
			// acquire an invented zero-argument declaration.
		}
	}
	return nil
}

func (b *goSigBuilder) addGoDeclSig(sym string) error {
	internal := b.goarch == "arm64" && strings.HasSuffix(sym, "<ABIInternal>")
	sym = goStripABISuffix(sym)
	resolved := b.resolve(sym)
	if resolved == "" {
		return nil
	}
	if _, ok := b.sigs[resolved]; ok && !internal {
		return nil
	}
	if ms, ok := goLookupManualSig(b.manualSig, resolved); ok {
		b.sigs[resolved] = ms
		return nil
	}

	declName := ""
	remoteKey := strings.ReplaceAll(sym, "∕", "/")
	remoteKey = strings.ReplaceAll(remoteKey, "·", ".")
	if local, ok := b.linknames[remoteKey]; ok {
		declName = local
	} else if strings.HasPrefix(resolved, b.pkgPath+".") {
		declName = strings.TrimPrefix(resolved, b.pkgPath+".")
	} else if strings.HasPrefix(sym, "·") {
		declName = strings.TrimPrefix(sym, "·")
	}
	if declName == "" {
		return nil
	}

	obj := b.scope.Lookup(declName)
	if obj == nil {
		return nil
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	// A Go declaration does not make a plain CALL/BL register-ABI. On x86
	// and ARM64 assembly calls its ABI0 wrapper unless the instruction says
	// ABIInternal. Keep result-only frame metadata too. ARM's outgoing-stack
	// bridge is separate; do not claim it merely by adding signature slots.
	withFrame := b.goarch == "amd64" || b.goarch == "386" || b.goarch == "arm64"
	fs, err := goFuncSigForDeclaredFunc(resolved, fn, b.goarch, b.sz, b.frameSz, withFrame)
	if err != nil {
		return err
	}
	if internal {
		fs.ARM64GoRegisterABI, err = DeriveARM64GoRegisterABI(fn, fs)
		if err != nil {
			return err
		}
	}
	b.sigs[resolved] = fs
	return nil
}

func goReferencedFunc(ins Instr) (base string, tailJump bool, ok bool) {
	switch string(ins.Op) {
	case "JMP", "B", "RET":
		tailJump = true
	case "CALL", "CALLNORESUME", "WASMCALL", "BL":
	default:
		return "", false, false
	}
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
		return "", false, false
	}
	s := strings.TrimSpace(ins.Args[0].Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return "", false, false
	}
	s = strings.TrimSuffix(s, "(SB)")
	base, off := goSplitSymPlusOff(s)
	if base == "" || off != 0 {
		return "", false, false
	}
	return base, tailJump, true
}

func goSplitSymPlusOff(s string) (base string, off int64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	sep := strings.LastIndexAny(s, "+-")
	if sep <= 0 || sep == len(s)-1 {
		return s, 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s[sep:]), 0, 64)
	if err != nil {
		return s, 0
	}
	return strings.TrimSpace(s[:sep]), n
}

func goLookupManualSig(manual func(string) (FuncSig, bool), resolved string) (FuncSig, bool) {
	if manual == nil {
		return FuncSig{}, false
	}
	fs, ok := manual(resolved)
	if !ok {
		return FuncSig{}, false
	}
	if fs.Name == "" {
		fs.Name = resolved
	}
	return fs, true
}

func goDeclNameForSymbol(sym string, linknames map[string]string) (string, error) {
	declName := strings.TrimPrefix(sym, "·")
	if strings.ContainsRune(declName, '·') {
		key := strings.ReplaceAll(sym, "∕", "/")
		key = strings.ReplaceAll(key, "·", ".")
		if local, ok := linknames[key]; ok {
			return local, nil
		}
		return "", fmt.Errorf("unsupported asm symbol name %q (no go:linkname mapping found)", sym)
	}
	return declName, nil
}

// DeriveGoFuncABI0Signature derives the complete ordinary signature and classic
// FP layout from an actual typed Go declaration. It supplies no native entry,
// hidden register, caller-memory or closure contract. Source authentication and
// source ABI selection remain the caller's separate obligations.
func DeriveGoFuncABI0Signature(name string, fn *types.Func, goarch string, sz types.Sizes) (FuncSig, error) {
	if name == "" || fn == nil {
		return FuncSig{}, fmt.Errorf("missing actual Go declaration for ABI0 layout")
	}
	if signature, ok := fn.Type().(*types.Signature); !ok || signature == nil {
		return FuncSig{}, fmt.Errorf("missing actual typed Go signature for ABI0 layout")
	}
	return goFuncSigForDeclaredFunc(name, fn, goarch, sz, sz, true)
}

func goFuncSigForDeclaredFunc(name string, fn *types.Func, goarch string, sz, frameSz types.Sizes, withFrame bool) (FuncSig, error) {
	if sz == nil {
		sz = types.SizesFor("gc", goarch)
	}
	if sz == nil {
		return FuncSig{}, fmt.Errorf("missing sizes for goarch %q", goarch)
	}
	if frameSz == nil {
		frameSz = sz
	}
	sig := fn.Type().(*types.Signature)
	if sig.Recv() != nil {
		return FuncSig{}, fmt.Errorf("methods in asm not supported: %s", fn.FullName())
	}
	if sig.Variadic() {
		return FuncSig{}, fmt.Errorf("variadic asm not supported: %s", fn.FullName())
	}
	if withFrame {
		args, frameParams, nextOff, err := goLLVMArgsAndFrameSlotsForTuple(sig.Params(), goarch, sz, frameSz, 0, false)
		if err != nil {
			return FuncSig{}, fmt.Errorf("%s: %w", fn.FullName(), err)
		}
		nextOff = goAlignOff(nextOff, int64(goWordSizeForSizes(goarch, frameSz)))
		retTys, frameResults, _, err := goLLVMArgsAndFrameSlotsForTuple(sig.Results(), goarch, sz, frameSz, nextOff, true)
		if err != nil {
			return FuncSig{}, fmt.Errorf("%s: %w", fn.FullName(), err)
		}
		result := FuncSig{Name: name, Args: args, Ret: goTupleRetType(retTys), Frame: FrameLayout{Params: frameParams, Results: frameResults}}
		if goarch == "arm64" {
			result.arm64FPReadDeclaration = arm64FPReadDeclarationForGo(result, sig, sz, frameSz)
			result.arm64ABI0Declaration = arm64ABI0DeclarationForGo(result, fn, sz, frameSz)
		}
		return result, nil
	}
	args, _, _, err := goLLVMArgsAndFrameSlotsForTuple(sig.Params(), goarch, sz, frameSz, 0, false)
	if err != nil {
		return FuncSig{}, fmt.Errorf("%s: %w", fn.FullName(), err)
	}
	retTys, _, _, err := goLLVMArgsAndFrameSlotsForTuple(sig.Results(), goarch, sz, frameSz, 0, false)
	if err != nil {
		return FuncSig{}, fmt.Errorf("%s: %w", fn.FullName(), err)
	}
	return FuncSig{Name: name, Args: args, Ret: goTupleRetType(retTys)}, nil
}

func goTupleRetType(ts []LLVMType) LLVMType {
	switch len(ts) {
	case 0:
		return Void
	case 1:
		return ts[0]
	default:
		parts := make([]string, 0, len(ts))
		for _, t := range ts {
			parts = append(parts, string(t))
		}
		return LLVMType("{ " + strings.Join(parts, ", ") + " }")
	}
}

func goLinknameRemoteToLocal(files []*ast.File) map[string]string {
	m := map[string]string{}
	for _, f := range files {
		if f == nil {
			continue
		}
		for _, cg := range f.Comments {
			if cg == nil {
				continue
			}
			for _, c := range cg.List {
				if c == nil {
					continue
				}
				line := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				if !strings.HasPrefix(line, "go:linkname") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) < 3 || parts[0] != "go:linkname" {
					continue
				}
				local := parts[1]
				remote := strings.ReplaceAll(parts[2], "∕", "/")
				remote = strings.ReplaceAll(remote, "·", ".")
				m[remote] = local
			}
		}
	}
	return m
}

func goExpandConsts(src []byte, pkgTypes *types.Package, imports map[string]*types.Package) []byte {
	if pkgTypes == nil || pkgTypes.Scope() == nil {
		return src
	}
	typeByPath := map[string]*types.Package{pkgTypes.Path(): pkgTypes}
	for path, tp := range imports {
		if tp != nil && tp.Scope() != nil && typeByPath[path] == nil {
			typeByPath[path] = tp
		}
	}
	lookupConst := func(tp *types.Package, name string) (string, bool) {
		if tp == nil || tp.Scope() == nil || name == "" {
			return "", false
		}
		obj := tp.Scope().Lookup(name)
		c, ok := obj.(*types.Const)
		if !ok || c == nil || c.Val() == nil {
			return "", false
		}
		switch c.Val().Kind() {
		case constant.Int:
			if i64, ok := constant.Int64Val(c.Val()); ok {
				return strconv.FormatInt(i64, 10), true
			}
			if u64, ok := constant.Uint64Val(c.Val()); ok {
				return strconv.FormatUint(u64, 10), true
			}
		case constant.String:
			return strconv.Quote(constant.StringVal(c.Val())), true
		}
		return "", false
	}

	expand := func(fragment []byte) []byte {
		fragment = goConstPlusRefRe.ReplaceAllFunc(fragment, func(m []byte) []byte {
			sub := goConstPlusRefRe.FindSubmatch(m)
			if len(sub) != 3 {
				return m
			}
			prefix := string(sub[1])
			name := string(sub[2])
			if i := strings.LastIndex(prefix, "/"); i >= 0 {
				path := prefix[:i]
				sym := prefix[i+1:]
				if tp := typeByPath[path]; tp != nil {
					if val, ok := lookupConst(tp, name); ok {
						return []byte(path + "/" + sym + "+" + val)
					}
				}
			}
			if j := strings.LastIndex(prefix, "."); j >= 0 {
				path := prefix[:j]
				sym := prefix[j+1:]
				if tp := typeByPath[path]; tp != nil {
					if val, ok := lookupConst(tp, name); ok {
						return []byte(path + "." + sym + "+" + val)
					}
				}
			}
			if val, ok := lookupConst(pkgTypes, name); ok {
				return []byte(prefix + "+" + val)
			}
			return m
		})

		return goConstRefRe.ReplaceAllFunc(fragment, func(m []byte) []byte {
			name := strings.TrimPrefix(string(m), "const_")
			if val, ok := lookupConst(pkgTypes, name); ok {
				return []byte(val)
			}
			return m
		})
	}
	return goExpandAssemblyMacroUses(src, expand)
}

// goExpandAsmHeaderTypes expands the struct size and field offset macros that
// cmd/compile writes to go_asm.h for the package's named struct types. The
// Plan 9 parser intentionally ignores #include, so the Go-aware translation
// path resolves these macros directly from the same go/types information it
// already uses for function signatures.
func goExpandAsmHeaderTypes(src []byte, pkgTypes *types.Package, goarch string) []byte {
	if pkgTypes == nil || pkgTypes.Scope() == nil {
		return src
	}
	sizes := types.SizesFor("gc", goarch)
	if sizes == nil {
		return src
	}
	referenced := make(map[string]bool)
	goExpandAssemblyMacroUses(src, func(fragment []byte) []byte {
		for _, ident := range goAsmHeaderIdentRe.FindAll(fragment, -1) {
			referenced[string(ident)] = true
		}
		return fragment
	})
	macros := make(map[string]string)
	for _, name := range pkgTypes.Scope().Names() {
		obj, ok := pkgTypes.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := obj.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		needSize := referenced[name+"__size"]
		needOffsets := false
		for i := 0; i < st.NumFields(); i++ {
			field := st.Field(i)
			if field.Name() != "_" && referenced[name+"_"+field.Name()] {
				needOffsets = true
				break
			}
		}
		if !needSize && !needOffsets {
			continue
		}
		if goTypeHasUnboundTypeParams(obj.Type()) {
			continue
		}
		if needSize {
			size := sizes.Sizeof(obj.Type())
			if size >= 0 {
				macros[name+"__size"] = strconv.FormatInt(size, 10)
			}
		}
		if !needOffsets {
			continue
		}
		fields := make([]*types.Var, st.NumFields())
		for i := range fields {
			fields[i] = st.Field(i)
		}
		for i, offset := range sizes.Offsetsof(fields) {
			field := fields[i]
			macro := name + "_" + field.Name()
			if field.Name() == "_" || !referenced[macro] || offset < 0 {
				continue
			}
			macros[macro] = strconv.FormatInt(offset, 10)
		}
	}
	if len(macros) == 0 {
		return src
	}
	return goExpandAssemblyMacroUses(src, func(fragment []byte) []byte {
		return goAsmHeaderIdentRe.ReplaceAllFunc(fragment, func(ident []byte) []byte {
			if value, ok := macros[string(ident)]; ok {
				return []byte(value)
			}
			return ident
		})
	})
}

func goTypeHasUnboundTypeParams(typ types.Type) bool {
	generic, ok := typ.(interface {
		TypeParams() *types.TypeParamList
		TypeArgs() *types.TypeList
	})
	return ok && generic.TypeParams().Len() != 0 && generic.TypeArgs().Len() == 0
}

// Keep CPP control operands and macro parameters as identifiers. Only free
// replacement-list references and ordinary assembly use generated values.
// The preprocessor still owns directive validity and conditional evaluation.
func goExpandAssemblyMacroUses(src []byte, expand func([]byte) []byte) []byte {
	lastControl := bytes.LastIndexByte(src, '#')
	if lastControl < 0 {
		return expand(src)
	}
	reader := newPPGoReader("<generated-header-expansion>", string(src))
	var tokens []AssemblyCPPToken
	readLine := func() error {
		for {
			physical, err := reader.next()
			if err != nil {
				return err
			}
			tokens = append(tokens, assemblyCPPPhysicalToken(reader, physical))
			if physical.kind == '\n' || physical.kind == scanner.EOF {
				return nil
			}
		}
	}
	var out bytes.Buffer
	start := 0
	finish := func() []byte {
		out.Write(expand(src[start:]))
		return out.Bytes()
	}
	for {
		tokens = tokens[:0]
		if err := readLine(); err != nil {
			return finish()
		}
		directive := len(tokens) > 1 && tokens[0].Text == "#"
		definition := directive && tokens[1].Kind == "identifier" && tokens[1].Text == "define"
		for definition && assemblyCPPContinuedLine(tokens) {
			if err := readLine(); err != nil {
				return finish()
			}
		}
		last := tokens[len(tokens)-1]
		if directive {
			out.Write(expand(src[start:tokens[0].Start]))
			protected := last.End
			var macro *AssemblyCPPMacroDefinition
			if definition {
				macro, _ = assemblyCPPPhysicalDefinition(tokens)
				if macro != nil && len(macro.Replacement) != 0 {
					protected = macro.Replacement[0].Start
				}
			}
			out.Write(src[tokens[0].Start:protected])
			start = protected
			if macro != nil && len(macro.Parameters) != 0 {
				parameters := make(map[string]bool, len(macro.Parameters))
				for _, name := range macro.Parameters {
					parameters[name] = true
				}
				for _, token := range macro.Replacement {
					if token.Kind == "identifier" && parameters[token.Text] {
						out.Write(expand(src[start:token.Start]))
						out.Write(src[token.Start:token.End])
						start = token.End
					}
				}
			}
			out.Write(expand(src[start:last.End]))
			start = last.End
		}
		if last.Kind == "eof" || last.End > lastControl {
			return finish()
		}
	}
}

func goLLVMTypeForType(t types.Type, goarch string) (LLVMType, error) {
	return goLLVMTypeForTypeWithSizes(t, goarch, types.SizesFor("gc", goarch))
}

func goLLVMTypeForTypeWithSizes(t types.Type, goarch string, sz types.Sizes) (LLVMType, error) {
	wordSize := goWordSizeForSizes(goarch, sz)
	switch tt := t.(type) {
	case *types.Basic:
		switch tt.Kind() {
		case types.Bool:
			return I1, nil
		case types.UnsafePointer:
			return Ptr, nil
		case types.Int8, types.Uint8:
			return LLVMType("i8"), nil
		case types.Int16, types.Uint16:
			return LLVMType("i16"), nil
		case types.Int32, types.Uint32:
			return I32, nil
		case types.Int64, types.Uint64:
			return I64, nil
		case types.Int, types.Uint, types.Uintptr:
			if wordSize == 8 {
				return I64, nil
			}
			return I32, nil
		case types.Float32:
			return LLVMType("float"), nil
		case types.Float64:
			return LLVMType("double"), nil
		case types.Complex64:
			return LLVMType("{ float, float }"), nil
		case types.Complex128:
			return LLVMType("{ double, double }"), nil
		case types.String:
			if wordSize == 8 {
				return LLVMType("{ ptr, i64 }"), nil
			}
			return LLVMType("{ ptr, i32 }"), nil
		default:
			return "", fmt.Errorf("unsupported basic type %s", tt.String())
		}
	case *types.Pointer:
		return Ptr, nil
	case *types.Signature, *types.Map, *types.Chan:
		// Go represents function, map, and channel values as pointer-sized
		// handles at an assembly boundary. Their internal layouts remain owned
		// by the compiler/runtime; Plan 9 assembly only transports the handle.
		return Ptr, nil
	case *types.Slice:
		if wordSize == 8 {
			return LLVMType("{ ptr, i64, i64 }"), nil
		}
		return LLVMType("{ ptr, i32, i32 }"), nil
	case *types.Interface:
		return LLVMType("{ ptr, ptr }"), nil
	case *types.Array:
		elem, err := goLLVMTypeForTypeWithSizes(tt.Elem(), goarch, sz)
		if err != nil {
			return "", err
		}
		return LLVMType(fmt.Sprintf("[%d x %s]", tt.Len(), elem)), nil
	case *types.Struct:
		if tt.NumFields() == 0 {
			return LLVMType("[0 x i8]"), nil
		}
		fields := make([]string, tt.NumFields())
		for i := range fields {
			field, err := goLLVMTypeForTypeWithSizes(tt.Field(i).Type(), goarch, sz)
			if err != nil {
				return "", err
			}
			fields[i] = string(field)
		}
		return LLVMType("{ " + strings.Join(fields, ", ") + " }"), nil
	case *types.Named:
		return goLLVMTypeForTypeWithSizes(tt.Underlying(), goarch, sz)
	default:
		// *types.Alias was added after the oldest Go version supported by this
		// module. Detect it by its stable reflect identity so the package still
		// compiles with Go 1.21, while newer go/types implementations can lower
		// an alias through its RHS just like a named type. Keep this probe in the
		// fallback path so common concrete types avoid reflection overhead.
		if reflect.TypeOf(t).String() == "*types.Alias" {
			return goLLVMTypeForTypeWithSizes(t.Underlying(), goarch, sz)
		}
		return "", fmt.Errorf("unsupported type %s", t.String())
	}
}

func goLLVMArgsAndFrameSlotsForTuple(tup *types.Tuple, goarch string, sz, frameSz types.Sizes, startOff int64, flattenAgg bool) (args []LLVMType, slots []FrameSlot, nextOff int64, err error) {
	if tup == nil || tup.Len() == 0 {
		return nil, nil, startOff, nil
	}

	off := startOff
	argIdx := 0
	for i := 0; i < tup.Len(); i++ {
		name := ""
		if flattenAgg {
			name = tup.At(i).Name()
		}
		t := tup.At(i).Type()
		a := int64(frameSz.Alignof(t))
		off = goAlignOff(off, a)

		parts, ok := goFramePartsForTypeWithSizes(t, goarch, sz, frameSz)
		if ok {
			if flattenAgg {
				for _, part := range parts {
					args = append(args, part.Type)
					slots = append(slots, FrameSlot{Offset: off + part.Offset, Type: part.Type, Index: argIdx, Field: -1, Name: name})
					argIdx++
				}
			} else {
				ty, e := goLLVMTypeForTypeWithSizes(t, goarch, sz)
				if e != nil {
					return nil, nil, 0, e
				}
				args = append(args, ty)
				for _, part := range parts {
					slots = append(slots, FrameSlot{Offset: off + part.Offset, Type: part.Type, Index: argIdx, Field: part.Field, Fields: part.Fields})
				}
				argIdx++
			}
			off += int64(frameSz.Sizeof(t))
			continue
		}

		ty, e := goLLVMTypeForTypeWithSizes(t, goarch, sz)
		if e != nil {
			return nil, nil, 0, e
		}
		args = append(args, ty)
		slots = append(slots, FrameSlot{Offset: off, Type: ty, Index: argIdx, Field: -1, Name: name})
		argIdx++
		off += int64(frameSz.Sizeof(t))
	}
	return args, slots, off, nil
}

type goFramePart struct {
	Offset int64
	Type   LLVMType
	Field  int
	Fields []int
}

func goFramePartsForType(t types.Type, goarch string) ([]goFramePart, bool) {
	sz := types.SizesFor("gc", goarch)
	return goFramePartsForTypeWithSizes(t, goarch, sz, sz)
}

func goFramePartsForTypeWithSizes(t types.Type, goarch string, sz, frameSz types.Sizes) ([]goFramePart, bool) {
	word := int64(goWordSizeForSizes(goarch, frameSz))
	wordTy := I64
	if goWordSizeForSizes(goarch, sz) == 4 {
		wordTy = I32
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch u.Kind() {
		case types.String:
			return []goFramePart{{Offset: 0, Type: Ptr, Field: 0}, {Offset: word, Type: wordTy, Field: 1}}, true
		case types.Complex64:
			return []goFramePart{{Offset: 0, Type: "float", Field: 0}, {Offset: 4, Type: "float", Field: 1}}, true
		case types.Complex128:
			return []goFramePart{{Offset: 0, Type: "double", Field: 0}, {Offset: 8, Type: "double", Field: 1}}, true
		}
	case *types.Slice:
		return []goFramePart{{Offset: 0, Type: Ptr, Field: 0}, {Offset: word, Type: wordTy, Field: 1}, {Offset: 2 * word, Type: wordTy, Field: 2}}, true
	case *types.Interface:
		return []goFramePart{{Offset: 0, Type: Ptr, Field: 0}, {Offset: word, Type: Ptr, Field: 1}}, true
	case *types.Struct:
		fields := make([]*types.Var, u.NumFields())
		for i := range fields {
			fields[i] = u.Field(i)
		}
		offsets := frameSz.Offsetsof(fields)
		var parts []goFramePart
		for i, field := range fields {
			children, ok := goNestedFrameParts(field.Type(), goarch, sz, frameSz, i, offsets[i])
			if !ok {
				return nil, false
			}
			parts = append(parts, children...)
		}
		return parts, true
	case *types.Array:
		var parts []goFramePart
		for i := int64(0); i < u.Len(); i++ {
			children, ok := goNestedFrameParts(u.Elem(), goarch, sz, frameSz, int(i), i*frameSz.Sizeof(u.Elem()))
			if !ok {
				return nil, false
			}
			parts = append(parts, children...)
		}
		return parts, true
	}
	return nil, false
}

func goNestedFrameParts(t types.Type, goarch string, sz, frameSz types.Sizes, field int, offset int64) ([]goFramePart, bool) {
	parts, aggregate := goFramePartsForTypeWithSizes(t, goarch, sz, frameSz)
	if !aggregate {
		typ, err := goLLVMTypeForTypeWithSizes(t, goarch, sz)
		if err != nil {
			return nil, false
		}
		parts = []goFramePart{{Type: typ, Field: -1}}
	}
	for i := range parts {
		part := &parts[i]
		path := []int{field}
		if len(part.Fields) != 0 {
			path = append(path, part.Fields...)
		} else if part.Field >= 0 {
			path = append(path, part.Field)
		}
		part.Offset += offset
		part.Field = field
		if len(path) > 1 {
			part.Fields = path
		}
	}
	return parts, true
}

func goWordSize(goarch string) int {
	switch goarch {
	case "amd64", "arm64", "wasm":
		return 8
	default:
		return 4
	}
}

func goWordSizeForSizes(goarch string, sz types.Sizes) int {
	if sz != nil {
		if size := sz.Sizeof(types.Typ[types.Uintptr]); size == 4 || size == 8 {
			return int(size)
		}
	}
	return goWordSize(goarch)
}

func goAlignOff(off, a int64) int64 {
	if a <= 1 {
		return off
	}
	m := off % a
	if m == 0 {
		return off
	}
	return off + (a - m)
}
