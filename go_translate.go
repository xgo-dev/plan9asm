package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/preprocess"
	"github.com/xgo-dev/plan9asm/internal/wasm"
	"github.com/xgo-dev/plan9asm/internal/x86"
)

type GoPackage struct {
	Path            string
	Types           *types.Package
	Imports         map[string]*types.Package
	Syntax          []*ast.File
	ImportSyntax    map[string][]*ast.File
	SourceSelection *GoSourceSelection
}

// GoModuleOptions configures TranslateGoModule.
//
// GOARCH is required and accepts "amd64", "386", "arm", "arm64", and "wasm".
// If ResolveSym is nil, the default resolver only strips ABI suffixes.
type GoModuleOptions struct {
	// SourceGoVersion is the Go assembler version for the input (for example, go1.20.14).
	SourceGoVersion    string
	SourcePreprocessed bool
	FileName           string
	GOOS               string
	GOARCH             string
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

	ResolveSym func(sym string) string
	KeepFunc   func(textSym, resolved string) bool
	ManualSig  func(resolved string) (FuncSig, bool)
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
		file, err = asm.ParsePreprocessed(arch, string(src))
		if err != nil {
			return nil, fmt.Errorf("%s: parse %s: %w", pkgPath, asmName, err)
		}
		if err := validatePreprocessedResolvedImmediates(file); err != nil {
			return nil, fmt.Errorf("%s: parse %s: %w", pkgPath, asmName, err)
		}
	} else {
		file, err = pkg.parseAssemblyForTarget(src, opt.GOOS, opt.GOARCH)
		if err != nil {
			return nil, fmt.Errorf("%s: parse %s: %w", pkgPath, asmName, err)
		}
	}
	file.SourceGoVersion = opt.SourceGoVersion
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

	sigs, err := goSigsForAsmFile(pkg, file, resolve, opt.GOARCH, opt.Sizes, opt.FrameSizes, opt.ManualSig)
	if err != nil {
		return nil, fmt.Errorf("%s: sigs %s: %w", pkgPath, asmName, err)
	}
	if opt.GOARCH == "arm64" && GoARM64ABI0TailDeclarationBindingNeeded(file) {
		sigs, err = BindGoARM64ABI0TailDeclarations(pkg, file, resolve, sigs)
		if err != nil {
			return nil, fmt.Errorf("%s: arm64 tail %s: %w", pkgPath, asmName, err)
		}
		for _, fn := range file.Funcs {
			if !strings.HasSuffix(goStripABISuffix(fn.Sym), "<>") {
				continue
			}
			resolved := resolve(goTextSymbolForResolution(fn.Sym))
			if _, ok := sigs[resolved]; !ok {
				return nil, fmt.Errorf("%s: sigs %s: missing signature for file-local assembly %q; supply ManualSig or use the native backend", pkgPath, asmName, resolved)
			}
		}
	}
	if err := validateGoClosureContextLoads(file, opt.GOARCH, resolve, sigs); err != nil {
		return nil, fmt.Errorf("%s: closure %s: %w", pkgPath, asmName, err)
	}
	volatileGlobals, err := collectValidatedImportedGlobals(pkg, file, resolve)
	if err != nil {
		return nil, fmt.Errorf("%s: globals %s: %w", pkgPath, asmName, err)
	}
	if opt.GOARCH == "386" {
		prepared, err := x86.PrepareFile(file, opt.GOARCH, opt.TargetTriple)
		if err != nil {
			return nil, fmt.Errorf("%s: frame %s: %w", pkgPath, asmName, err)
		}
		callee := func(s string) string { return resolve(goTextSymbolForResolution(s)) }
		for _, fn := range prepared.Funcs {
			sig, ok := sigs[resolve(goTextSymbolForResolution(fn.Sym))]
			if !ok || len(sig.ArgRegs) != 0 {
				continue
			}
			if len(sig.Frame.Results) == 0 && !x86.FuncUsesX87OrMMX(fn) && !funcUsesPhysical386SP(fn) {
				continue
			}
			if _, err := x86.CheckPreparedABI0ResultInit(fn, sig, "386", callee, sigs, opt.X87Mode, opt.TargetTriple); err != nil {
				return nil, fmt.Errorf("%s: frame %s: %w", pkgPath, asmName, err)
			}
		}
	}
	if opt.GOARCH == "amd64" {
		if err := validateAMD64PhysicalFrameLeasesForTarget(file, resolve, sigs, opt.X87Mode, opt.TargetTriple); err != nil {
			return nil, fmt.Errorf("%s: frame %s: %w", pkgPath, asmName, err)
		}
	}
	mod, err := TranslateModule(file, Options{
		TargetTriple:    opt.TargetTriple,
		ResolveSym:      resolve,
		Sigs:            sigs,
		Goarch:          opt.GOARCH,
		WASMABI:         opt.WASMABI,
		X87Mode:         opt.X87Mode,
		AnnotateSource:  opt.AnnotateSource,
		VolatileGlobals: volatileGlobals,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: translate %s: %w", pkgPath, asmName, err)
	}

	funcs := make([]GoFunction, 0, len(file.Funcs))
	for _, fn := range file.Funcs {
		funcs = append(funcs, GoFunction{TextSymbol: fn.Sym, ResolvedSymbol: resolve(goTextSymbolForResolution(fn.Sym))})
	}

	return &GoModuleTranslation{Module: mod, Signatures: sigs, Functions: funcs}, nil
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
		sigs:      make(map[string]FuncSig, len(file.Funcs)),
		localSigs: make(map[string]bool),
		scope:     pkg.Types.Scope(),
		sz:        sz,
		frameSz:   frameSz,
		linknames: goLinknameRemoteToLocal(pkg.Syntax),
		pkgPath:   pkg.Path,
		resolve:   resolve,
		goarch:    goarch,
		manualSig: manualSig,
	}
	if b.pkgPath == "" {
		b.pkgPath = pkg.Types.Path()
	}
	if err := b.addDeclaredFuncSigs(file); err != nil {
		return nil, err
	}
	if err := b.addReferencedFuncSigs(file); err != nil {
		return nil, err
	}
	if goarch == "386" {
		markNonReturningGoCallees(pkg, resolve, b.sigs)
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
			if wasm.NeedsIncomingContext(fn) {
				fs.WASMContext = Ptr
			}
			b.sigs[resolved] = fs
		}
	}
	// A file-local symbol does not imply a zero-argument C or Go signature.
	// Keep signatures obtained from declarations, supported tail-call inference,
	// or ManualSig; raw register entry points require the native backend.
	// For ARM64 ABI0 private tail helpers, only defer the specific helper<>
	// targets branched to by an ABI0 root; any other unbound <> symbol fails now.
	var deferredTailTargets map[string]bool
	if b.goarch == "arm64" && GoARM64ABI0TailDeclarationBindingNeeded(file) {
		deferredTailTargets = arm64PrivateTailTargetSet(file, resolve)
	}
	for resolved := range b.localSigs {
		if _, ok := b.sigs[resolved]; !ok && !deferredTailTargets[resolved] {
			return nil, fmt.Errorf("missing signature for file-local assembly %q; supply ManualSig or use the native backend", resolved)
		}
	}
	return b.sigs, nil
}

// A call to a Go function consisting solely of builtin panic cannot reach
// the next assembly instruction. Require an unshadowed builtin and the same
// declaration position as the type-checked function.
func markNonReturningGoCallees(pkg GoPackage, resolve func(string) string, sigs map[string]FuncSig) {
	if pkg.Types.Scope().Lookup("panic") != nil {
		return
	}
	for _, src := range pkg.Syntax {
		if src == nil || len(src.Imports) != 0 {
			continue
		}
		for _, decl := range src.Decls {
			f, ok := decl.(*ast.FuncDecl)
			if !ok || f.Recv != nil || f.Body == nil || len(f.Body.List) != 1 || f.Type.Params.NumFields() != 0 || f.Type.Results.NumFields() != 0 || f.Type.TypeParams.NumFields() != 0 {
				continue
			}
			name := resolve("·" + f.Name.Name)
			sig, ok := sigs[name]
			if !ok || !f.Name.Pos().IsValid() {
				continue
			}
			obj, ok := pkg.Types.Scope().Lookup(f.Name.Name).(*types.Func)
			if !ok || obj.Pos() != f.Name.Pos() {
				continue
			}
			expr, ok := f.Body.List[0].(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expr.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			id, ok := call.Fun.(*ast.Ident)
			if ok && id.Name == "panic" {
				sig.Attrs = strings.TrimSpace(sig.Attrs + " noreturn")
				sigs[name] = sig
			}
		}
	}
}

func arm64PrivateTailTargetSet(file *File, resolve func(string) string) map[string]bool {
	targets := make(map[string]bool)
	for _, root := range file.Funcs {
		if strings.Contains(root.Sym, "<") {
			continue
		}
		for _, ins := range root.Instrs {
			if name, ok := arm64PrivateTailTarget(ins); ok {
				targets[resolve(goTextSymbolForResolution(name))] = true
			}
		}
	}
	return targets
}

func wasmUsesNativeReturn(fn Func) bool {
	for _, ins := range fn.Instrs {
		if asm.NormalizeInstructionOpcode(ins.Op) == "WASMRETURN" {
			return true
		}
	}
	return false
}

type goSigBuilder struct {
	sigs      map[string]FuncSig
	localSigs map[string]bool
	scope     *types.Scope
	sz        types.Sizes
	frameSz   types.Sizes
	linknames map[string]string
	pkgPath   string
	resolve   func(sym string) string
	goarch    string
	manualSig func(string) (FuncSig, bool)
}

func (b *goSigBuilder) addDeclaredFuncSigs(file *File) error {
	for i := range file.Funcs {
		textSym := file.Funcs[i].Sym
		sym := goStripABISuffix(textSym)
		resolved := b.resolve(goTextSymbolForResolution(textSym))
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

func (b *goSigBuilder) addReferencedFuncSigs(file *File) error {
	for _, fn := range file.Funcs {
		callerResolved := b.resolve(goTextSymbolForResolution(fn.Sym))
		callerSig, hasCallerSig := b.sigs[callerResolved]
		for _, ins := range fn.Instrs {
			if b.goarch == "386" {
				if sym := x86.AddressedFunctionCandidate(ins); sym != "" {
					if err := b.addGoDeclSig(sym); err != nil {
						return err
					}
				}
			}
			base, tailJump, ok := goReferencedFunc(ins)
			if !ok {
				continue
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
			if tailJump && hasCallerSig && !(b.goarch == "arm64" && strings.HasSuffix(base, "<>")) {
				// Best-effort fallback for helper<> tail-jumps where the callee is an
				// internal asm label with no Go declaration. Callers can override this
				// via ManualSig when the inferred signature is not identical.
				fs := callerSig
				fs.Name = targetResolved
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
	sym = goStripABISuffix(sym)
	resolved := b.resolve(sym)
	if resolved == "" {
		return nil
	}
	if _, ok := b.sigs[resolved]; ok {
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
	fs, err := goFuncSigForDeclaredFunc(resolved, fn, b.goarch, b.sz, b.frameSz, true)
	if err != nil {
		return err
	}
	b.sigs[resolved] = fs
	return nil
}

func goReferencedFunc(ins Instr) (base string, tailJump bool, ok bool) {
	switch string(ins.Op) {
	case "JMP", "B":
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
// FP layout from an actual typed Go declaration.
func DeriveGoFuncABI0Signature(name string, fn *types.Func, goarch string, sz types.Sizes) (FuncSig, error) {
	if name == "" || fn == nil {
		return FuncSig{}, fmt.Errorf("missing actual Go declaration for ABI0 layout")
	}
	if signature, ok := fn.Type().(*types.Signature); !ok || signature == nil {
		return FuncSig{}, fmt.Errorf("missing actual typed Go signature for ABI0 layout")
	}
	return goFuncSigForDeclaredFunc(name, fn, goarch, sz, sz, true)
}

func validateAMD64PhysicalFrameLeases(file *File, resolve func(string) string, sigs map[string]FuncSig) error {
	return validateAMD64PhysicalFrameLeasesForTarget(file, resolve, sigs, X87Auto, "")
}

func validateAMD64PhysicalFrameLeasesForTarget(file *File, resolve func(string) string, sigs map[string]FuncSig, x87Mode X87Mode, targetTriple string) error {
	checkedLeases := make(map[uintptr]bool)
	resolveCallee := func(s string) string { return resolve(goStripABISuffix(s)) }
	for _, fn := range file.Funcs {
		name := resolve(goTextSymbolForResolution(fn.Sym))
		sig, ok := sigs[name]
		if !funcUsesPhysicalAMD64SP(fn) {
			// Ordinary ABI0 functions (non-physical SP) with declared Go result
			// slots — or any function touching x87/MMX (including void pointer-out
			// kernels) — require CFG + byte-exact result/register/FP/SP/x87
			// initialization verification before translation.
			if ok && len(sig.ArgRegs) == 0 && (len(sig.Frame.Results) > 0 || x86.FuncUsesX87OrMMX(fn)) &&
				!strings.Contains(strings.TrimSuffix(fn.Sym, "<>"), "<") {
				if _, err := x86.CheckABI0ResultInitWithOptions(fn, sig, "amd64", resolveCallee, sigs, x87Mode, targetTriple); err != nil {
					return err
				}
			}
			continue
		}
		if !ok {
			return fmt.Errorf("%w: missing signature for physical AMD64 frame %q", ErrProbeNeedsContext, name)
		}
		// If a live lease was attached by GoAMD64FrameSource.BindFixedLocal, verify it is still live
		// (deduplicated per shared lease closure so multi-function files hash snapshots once).
		if sig.FrameLease != nil {
			leasePtr := reflect.ValueOf(sig.FrameLease).Pointer()
			if !checkedLeases[leasePtr] {
				if err := sig.FrameLease(); err != nil {
					return err
				}
				checkedLeases[leasePtr] = true
			}
			if x87Mode == X87Software && x86.FuncUsesX87OrMMX(fn) {
				if _, err := x86.CheckABI0ResultInitWithOptions(fn, sig, "amd64", resolveCallee, sigs, x87Mode, targetTriple); err != nil {
					return err
				}
			}
			continue
		}
		// Without a captured physical-frame owner, check whether any outgoing
		// CALL lacks a declared signature in sigs (e.g. runtime.memmove) or
		// whether the function violates ABI0 register init / SP confinement.
		for _, ins := range fn.Instrs {
			if strings.ToUpper(string(ins.Op)) == "CALL" && len(ins.Args) == 1 && ins.Args[0].Kind == OpSym {
				raw := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
				callee := resolve(goStripABISuffix(raw))
				if callee == "runtime.entersyscall" || callee == "runtime.exitsyscall" {
					continue
				}
				if _, hasCallee := sigs[callee]; !hasCallee {
					return fmt.Errorf("%w: AMD64 physical frame call %q requires captured source owner", ErrProbeNeedsContext, callee)
				}
			}
		}
		if _, err := x86.CheckABI0ResultInitWithOptions(fn, sig, "amd64", resolveCallee, sigs, x87Mode, targetTriple); err != nil {
			return err
		}
	}
	return nil
}

// collectValidatedImportedGlobals identifies cross-package mutable Go variables
// referenced by assembly (SB) operands and validates that their owning package
// syntax matches the type-checked dependency graph when ImportSyntax is present.
func collectValidatedImportedGlobals(pkg GoPackage, file *File, resolve func(string) string) (map[string]bool, error) {
	if pkg.Types == nil {
		return nil, nil
	}
	importedByPath := map[string]*types.Package{}
	for _, imp := range pkg.Types.Imports() {
		if imp != nil {
			importedByPath[imp.Path()] = imp
		}
	}
	definedData := map[string]bool{}
	for _, g := range file.Globl {
		definedData[resolve(goStripABISuffix(g.Sym))] = true
	}
	for _, d := range file.Data {
		definedData[resolve(goStripABISuffix(d.Sym))] = true
	}
	definedFuncs := map[string]bool{}
	for _, fn := range file.Funcs {
		definedFuncs[resolve(goTextSymbolForResolution(fn.Sym))] = true
	}

	volatile := map[string]bool{}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			op := strings.ToUpper(string(ins.Op))
			if op == "CALL" || op == "JMP" || op == "B" || op == "BL" {
				continue
			}
			for _, arg := range ins.Args {
				if arg.Kind != OpSym {
					continue
				}
				s := strings.TrimSpace(arg.Sym)
				if strings.HasPrefix(s, "$") || !strings.HasSuffix(s, "(SB)") {
					continue
				}
				base, _, ok := asm.ParseSBRef(s)
				if !ok || strings.HasPrefix(base, "·") || (!strings.Contains(base, "·") && !strings.Contains(base, "/")) {
					continue
				}
				res := resolve(base)
				if definedData[res] || definedFuncs[res] {
					continue
				}
				dot := strings.LastIndexByte(res, '.')
				if dot <= 0 || dot == len(res)-1 {
					continue
				}
				impPath, varName := res[:dot], res[dot+1:]
				if impPath == pkg.Path || impPath == pkg.Types.Path() {
					continue
				}
				// Check if pkg actually imports impPath.
				typeCheckedImp := importedByPath[impPath]
				if typeCheckedImp == nil {
					continue
				}
				// Validate pkg.Imports[impPath] matches typeCheckedImp.
				suppliedImp, inImports := pkg.Imports[impPath]
				if !inImports || suppliedImp == nil || suppliedImp != typeCheckedImp {
					return nil, fmt.Errorf("%w: imported global %s lacks matching dependency package %q", ErrProbeNeedsContext, res, impPath)
				}
				v, ok := suppliedImp.Scope().Lookup(varName).(*types.Var)
				if !ok || v == nil {
					continue
				}
				// When ImportSyntax map is provided by the caller (e.g. llgo), require
				// matching variable syntax with compatible declared type.
				if pkg.ImportSyntax != nil {
					files := pkg.ImportSyntax[impPath]
					if len(files) == 0 {
						return nil, fmt.Errorf("%w: imported global %s lacks dependency syntax for %q", ErrProbeNeedsContext, res, impPath)
					}
					if err := verifyImportedVarSyntax(files, varName, v.Type(), suppliedImp); err != nil {
						return nil, fmt.Errorf("%w: imported global %s: %v", ErrProbeNeedsContext, res, err)
					}
				}
				volatile[res] = true
			}
		}
	}
	if len(volatile) == 0 {
		return nil, nil
	}
	return volatile, nil
}

func verifyImportedVarSyntax(files []*ast.File, varName string, wantType types.Type, pkg *types.Package) error {
	for _, f := range files {
		if f == nil {
			continue
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, id := range vs.Names {
					if id.Name != varName {
						continue
					}
					if vs.Type != nil && !astTypeMatchesGoType(vs.Type, wantType, pkg) {
						return fmt.Errorf("syntax type for %q differs from checked type %s", varName, wantType.String())
					}
					return nil
				}
			}
		}
	}
	return fmt.Errorf("variable %q not declared in dependency syntax", varName)
}

func astTypeMatchesGoType(expr ast.Expr, t types.Type, pkg *types.Package) bool {
	if expr == nil || t == nil {
		return false
	}
	for {
		if p, ok := expr.(*ast.ParenExpr); ok {
			expr = p.X
			continue
		}
		break
	}
	switch e := expr.(type) {
	case *ast.Ident:
		switch tt := t.(type) {
		case *types.Basic:
			if e.Name == tt.Name() {
				return true
			}
			return (e.Name == "byte" && tt.Kind() == types.Uint8) ||
				(e.Name == "rune" && tt.Kind() == types.Int32)
		case *types.Named:
			if tt.Obj() == nil || e.Name != tt.Obj().Name() {
				return false
			}
			return tt.Obj().Pkg() == nil || pkg == nil || tt.Obj().Pkg() == pkg
		case *types.Interface:
			return e.Name == "any" && tt.Empty()
		default:
			if reflect.TypeOf(t).String() == "*types.Alias" {
				return astTypeMatchesGoType(expr, t.Underlying(), pkg)
			}
			return false
		}
	case *ast.SelectorExpr:
		switch tt := t.(type) {
		case *types.Basic:
			return e.Sel.Name == "Pointer" && tt.Kind() == types.UnsafePointer
		case *types.Named:
			return tt.Obj() != nil && e.Sel.Name == tt.Obj().Name() && tt.Obj().Pkg() != nil
		default:
			if reflect.TypeOf(t).String() == "*types.Alias" {
				return astTypeMatchesGoType(expr, t.Underlying(), pkg)
			}
			return false
		}
	case *ast.StarExpr:
		pt, ok := t.Underlying().(*types.Pointer)
		return ok && astTypeMatchesGoType(e.X, pt.Elem(), pkg)
	case *ast.ArrayType:
		if e.Len == nil {
			sl, ok := t.Underlying().(*types.Slice)
			return ok && astTypeMatchesGoType(e.Elt, sl.Elem(), pkg)
		}
		ar, ok := t.Underlying().(*types.Array)
		if !ok || !astTypeMatchesGoType(e.Elt, ar.Elem(), pkg) {
			return false
		}
		if lit, ok := e.Len.(*ast.BasicLit); ok && lit.Kind == token.INT {
			if n, err := strconv.ParseInt(lit.Value, 0, 64); err == nil && n != ar.Len() {
				return false
			}
		}
		return true
	case *ast.StructType:
		st, ok := t.Underlying().(*types.Struct)
		if !ok {
			return false
		}
		idx := 0
		if e.Fields != nil {
			for _, f := range e.Fields.List {
				count := len(f.Names)
				if count == 0 {
					count = 1
				}
				for i := 0; i < count; i++ {
					if idx >= st.NumFields() {
						return false
					}
					sf := st.Field(idx)
					if len(f.Names) > 0 && f.Names[i].Name != sf.Name() {
						return false
					}
					if !astTypeMatchesGoType(f.Type, sf.Type(), pkg) {
						return false
					}
					idx++
				}
			}
		}
		return idx == st.NumFields()
	case *ast.MapType:
		mp, ok := t.Underlying().(*types.Map)
		return ok && astTypeMatchesGoType(e.Key, mp.Key(), pkg) && astTypeMatchesGoType(e.Value, mp.Elem(), pkg)
	case *ast.ChanType:
		ch, ok := t.Underlying().(*types.Chan)
		return ok && astTypeMatchesGoType(e.Value, ch.Elem(), pkg)
	case *ast.InterfaceType:
		_, ok := t.Underlying().(*types.Interface)
		return ok
	case *ast.FuncType:
		_, ok := t.Underlying().(*types.Signature)
		return ok
	default:
		return false
	}
}

func validatePreprocessedResolvedImmediates(file *File) error {
	if file == nil {
		return nil
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				if arg.Kind == OpImm && arg.ImmRaw != "" {
					return fmt.Errorf("%s: unresolved symbolic immediate %q", fn.Sym, arg.ImmRaw)
				}
				if arg.Kind == OpSym {
					s := strings.TrimSpace(arg.Sym)
					if strings.HasPrefix(s, "$") && !strings.Contains(s, "(") {
						return fmt.Errorf("%s: unresolved symbolic immediate %q", fn.Sym, s)
					}
				}
			}
		}
	}
	return nil
}

// validateGoClosureContextLoads rejects unmodified gc NEEDCTXT assembly entries
// that dereference the hidden closure context register (DX on 386/amd64, R26 on
// arm64) without any Go/helper parameter or prior write initializing it.
func validateGoClosureContextLoads(file *File, goarch string, resolve func(string) string, sigs map[string]FuncSig) error {
	var ctxtReg Reg
	switch goarch {
	case "amd64", "386":
		ctxtReg = DX
	case "arm64":
		ctxtReg = Reg("R26")
	default:
		return nil
	}
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") {
			continue
		}
		resolved := resolve(goTextSymbolForResolution(fn.Sym))
		sig, ok := sigs[resolved]
		if !ok {
			continue
		}
		passedInArgReg := false
		for _, r := range sig.ArgRegs {
			if r == ctxtReg {
				passedInArgReg = true
				break
			}
		}
		if passedInArgReg {
			continue
		}
		if funcWritesReg(fn, goarch, ctxtReg) {
			continue
		}
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				if arg.Kind == OpMem && arg.Mem.Base == ctxtReg {
					return fmt.Errorf("%w: uninitialized closure context load %s", ErrProbeNeedsContext, strings.TrimSpace(ins.Raw))
				}
			}
		}
	}
	return nil
}

func funcWritesReg(fn Func, goarch string, target Reg) bool {
	isTarget := func(r Reg) bool {
		if r == target {
			return true
		}
		if target == DX && (r == DL || r == DH) {
			return true
		}
		return false
	}
	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		if target == DX {
			switch op {
			case "CPUID", "XGETBV", "RDTSC", "RDTSCP", "SYSCALL", "CALL",
				"MULQ", "MULL", "MULW", "IMULQ", "IMULL", "DIVQ", "DIVL", "IDIVQ", "IDIVL",
				"CQO", "CDQ", "CWD", "POPQ", "POPL", "POPAL":
				return true
			}
		}
		if target == Reg("R26") && (op == "BL" || op == "CALL") {
			return true
		}
		if len(ins.Args) == 0 {
			continue
		}
		// Check destination operand (last arg on Plan 9 asm, or both args for XCHG/XADD/LDP/etc.).
		dst := ins.Args[len(ins.Args)-1]
		if dst.Kind == OpReg && isTarget(dst.Reg) {
			switch op {
			case "CMPQ", "CMPL", "CMPW", "CMPB", "TESTQ", "TESTL", "TESTW", "TESTB",
				"CMP", "CMN", "TST", "TSTW", "CBZ", "CBNZ", "TBZ", "TBNZ":
				// Comparisons only read operands.
			default:
				return true
			}
		}
		if dst.Kind == OpRegList {
			for _, r := range dst.RegList {
				if isTarget(r) {
					return true
				}
			}
		}
		if len(ins.Args) >= 2 && (strings.HasPrefix(op, "XCHG") || strings.HasPrefix(op, "XADD") || strings.HasPrefix(op, "LDP") || strings.HasPrefix(op, "LDAXP")) {
			for _, arg := range ins.Args {
				if arg.Kind == OpReg && isTarget(arg.Reg) {
					return true
				}
			}
		}
	}
	return false
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
		return FuncSig{Name: name, Args: args, Ret: goTupleRetType(retTys), Frame: FrameLayout{Params: frameParams, Results: frameResults}}, nil
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

// ParseAssembly parses assembly with the constants and field offsets of the
// selected Go package and architecture.
func (pkg GoPackage) ParseAssembly(src []byte, goarch string) (*File, error) {
	return pkg.parseAssemblyForTarget(src, "", goarch)
}

func (pkg GoPackage) parseAssemblyForTarget(src []byte, goos, goarch string) (*File, error) {
	arch, err := goArchFor(goarch)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(src, []byte("const_")) {
		src = goExpandConsts(src, pkg.Types, pkg.Imports)
	}
	if bytes.Contains(src, []byte("go_asm.h")) {
		src = goExpandAsmHeaderTypes(src, pkg.Types, goarch)
	}
	expanded, err := preprocess.PreprocessWithDefines(string(src), GoAssemblerDefines(goos, goarch))
	if err != nil {
		return nil, err
	}
	return asm.ParsePreprocessed(arch, expanded)
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

	src = goConstPlusRefRe.ReplaceAllFunc(src, func(m []byte) []byte {
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

	return goConstRefRe.ReplaceAllFunc(src, func(m []byte) []byte {
		name := strings.TrimPrefix(string(m), "const_")
		if val, ok := lookupConst(pkgTypes, name); ok {
			return []byte(val)
		}
		return m
	})
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
	macros := make(map[string]string)
	for _, name := range pkgTypes.Scope().Names() {
		obj, ok := pkgTypes.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := obj.Type().Underlying().(*types.Struct)
		if !ok || goTypeHasUnboundTypeParams(obj.Type()) {
			continue
		}
		size := sizes.Sizeof(obj.Type())
		if size < 0 {
			continue
		}
		macros[name+"__size"] = strconv.FormatInt(size, 10)
		fields := make([]*types.Var, st.NumFields())
		for i := range fields {
			fields[i] = st.Field(i)
		}
		for i, offset := range sizes.Offsetsof(fields) {
			field := fields[i]
			if field.Name() == "_" || offset < 0 {
				continue
			}
			macros[name+"_"+field.Name()] = strconv.FormatInt(offset, 10)
		}
	}
	if len(macros) == 0 {
		return src
	}
	return goAsmHeaderIdentRe.ReplaceAllFunc(src, func(ident []byte) []byte {
		if value, ok := macros[string(ident)]; ok {
			return []byte(value)
		}
		return ident
	})
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
