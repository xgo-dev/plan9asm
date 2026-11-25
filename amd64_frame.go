package plan9asm

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/preprocess"
	"github.com/xgo-dev/plan9asm/internal/x86"
)

// GoAMD64FrameCaptureRequest identifies the source package directory, Go SDK
// binary, assembly file, target, and environment for binding an AMD64 physical
// stack-frame assembly translation.
type GoAMD64FrameCaptureRequest struct {
	GoBinary     string
	Directory    string
	AssemblyFile string
	Target       string
	Environment  []string
}

// GoAMD64DownloadedFrameCaptureRequest captures a physical AMD64 frame source
// from a downloaded module version.
type GoAMD64DownloadedFrameCaptureRequest struct {
	Original      GoAMD64FrameCaptureRequest
	SourceModule  string
	SourceVersion string
}

// GoAMD64FrameSource holds a verified snapshot of a package's Go and assembly
// source files and issues live frame leases for TranslateGoModule.
type GoAMD64FrameSource struct {
	mu           sync.Mutex
	closed       bool
	directory    string
	assemblyFile string
	goBinary     string
	goroot       string
	goos         string
	goarch       string
	environment  []string
	snapshots    map[string][32]byte // relative path -> SHA256 digest at capture
	asmBytes     []byte
}

// CaptureGoAMD64FrameSource captures and snapshots an AMD64 package directory
// after validating the selected Go toolchain binary.
func CaptureGoAMD64FrameSource(ctx context.Context, pkg GoPackage, request GoAMD64FrameCaptureRequest) (*GoAMD64FrameSource, error) {
	return captureGoAMD64FrameSource(ctx, pkg, request, "", "", "")
}

// CaptureGoAMD64SDKFrameSource captures an AMD64 package located inside GOROOT/src.
func CaptureGoAMD64SDKFrameSource(ctx context.Context, pkg GoPackage, request GoAMD64FrameCaptureRequest) (*GoAMD64FrameSource, error) {
	return captureGoAMD64FrameSource(ctx, pkg, request, "sdk", "", "")
}

// CaptureGoAMD64DownloadedFrameSource captures an AMD64 package from a
// downloaded module version inside GOMODCACHE.
func CaptureGoAMD64DownloadedFrameSource(ctx context.Context, pkg GoPackage, request GoAMD64DownloadedFrameCaptureRequest) (*GoAMD64FrameSource, error) {
	if request.SourceModule == "" || request.SourceVersion == "" ||
		strings.Contains(request.SourceModule, "..") || strings.Contains(request.SourceVersion, "..") ||
		strings.ContainsAny(request.SourceVersion, `/\`) {
		return nil, fmt.Errorf("%w: downloaded AMD64 frame source requires valid module path and version", ErrProbeNeedsContext)
	}
	return captureGoAMD64FrameSource(ctx, pkg, request.Original, "downloaded", request.SourceModule, request.SourceVersion)
}

func captureGoAMD64FrameSource(ctx context.Context, pkg GoPackage, request GoAMD64FrameCaptureRequest, provenance, sourceModule, sourceVersion string) (*GoAMD64FrameSource, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: AMD64 frame capture requires a live context", ErrProbeNeedsContext)
	}
	goos, goarch, ok := strings.Cut(request.Target, "/")
	if !ok || goos == "" || goarch != "amd64" {
		return nil, fmt.Errorf("%w: unsupported AMD64 frame target %q", ErrProbeNeedsContext, request.Target)
	}
	if request.GoBinary == "" || request.Directory == "" || request.AssemblyFile == "" {
		return nil, fmt.Errorf("%w: incomplete AMD64 frame capture request", ErrProbeNeedsContext)
	}
	if strings.ContainsAny(request.AssemblyFile, `/\`) || request.AssemblyFile == "." || request.AssemblyFile == ".." {
		return nil, fmt.Errorf("%w: invalid assembly filename %q", ErrProbeNeedsContext, request.AssemblyFile)
	}
	// Verify the Go binary is a real toolchain (rejects fake/broken SDK binaries).
	stdout, _, err := gotoolprofile.RunBounded(ctx, request.Directory, request.Environment, request.GoBinary, "version")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(stdout)), "go version go1.") {
		return nil, fmt.Errorf("%w: invalid Go toolchain binary for AMD64 frame source: %v", ErrProbeNeedsContext, err)
	}

	dir, err := canonicalRealPath(request.Directory)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve package directory: %v", ErrProbeNeedsContext, err)
	}

	goroot := resolveAMD64FrameGOROOT(ctx, dir, request.Environment, request.GoBinary)
	if goroot != "" {
		if resolved, rerr := canonicalRealPath(goroot); rerr == nil {
			goroot = resolved
		}
	}

	switch provenance {
	case "sdk":
		sdkSrc := filepath.Join(goroot, "src")
		if goroot == "" || !isPathWithinDir(sdkSrc, dir) {
			return nil, fmt.Errorf("%w: SDK AMD64 frame directory %q is outside GOROOT/src (%q)", ErrProbeNeedsContext, dir, sdkSrc)
		}
	case "downloaded":
		modCache := resolveAMD64FrameModCache(ctx, dir, request.Environment, request.GoBinary)
		if modCache != "" {
			if resolved, rerr := canonicalRealPath(modCache); rerr == nil {
				modCache = resolved
			}
		}
		modRoot := filepath.Join(modCache, filepath.FromSlash(escapeGoModulePath(sourceModule)+"@"+escapeGoModulePath(sourceVersion)))
		if modCache == "" || !isPathWithinDir(modRoot, dir) {
			return nil, fmt.Errorf("%w: downloaded AMD64 frame directory %q is outside module cache root %q", ErrProbeNeedsContext, dir, modRoot)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: read package directory: %v", ErrProbeNeedsContext, err)
	}
	snapshots := make(map[string][32]byte)
	var asmBytes []byte
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".s") && !strings.HasSuffix(name, ".h") {
			continue
		}
		fullPath := filepath.Join(dir, name)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("%w: read %s: %v", ErrProbeNeedsContext, name, err)
		}
		snapshots[fullPath] = sha256.Sum256(data)
		if name == request.AssemblyFile {
			asmBytes = data
		}
	}
	if asmBytes == nil {
		return nil, fmt.Errorf("%w: assembly file %q not found in %q", ErrProbeNeedsContext, request.AssemblyFile, dir)
	}

	src := &GoAMD64FrameSource{
		directory:    dir,
		assemblyFile: request.AssemblyFile,
		goBinary:     request.GoBinary,
		goroot:       goroot,
		goos:         goos,
		goarch:       goarch,
		environment:  append([]string(nil), request.Environment...),
		snapshots:    snapshots,
		asmBytes:     asmBytes,
	}
	// Hash any headers included by the captured assembly file (confined to the
	// package directory and GOROOT/pkg/include) so post-capture edits to included
	// headers are caught by Verify.
	if err := src.snapshotIncludedHeaders(pkg); err != nil {
		return nil, err
	}
	return src, nil
}

func resolveAMD64FrameGOROOT(ctx context.Context, dir string, env []string, goBinary string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "GOROOT" && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if out, _, err := gotoolprofile.RunBounded(ctx, dir, env, goBinary, "env", "GOROOT"); err == nil {
		if gr := strings.TrimSpace(string(out)); gr != "" {
			return gr
		}
	}
	return filepath.Dir(filepath.Dir(goBinary))
}

func resolveAMD64FrameModCache(ctx context.Context, dir string, env []string, goBinary string) string {
	var gopath string
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if k == "GOMODCACHE" && v != "" {
			return v
		}
		if k == "GOPATH" && v != "" {
			gopath = v
		}
	}
	if gopath != "" {
		first := filepath.SplitList(gopath)[0]
		if first != "" {
			return filepath.Join(first, "pkg", "mod")
		}
	}
	if out, _, err := gotoolprofile.RunBounded(ctx, dir, env, goBinary, "env", "GOMODCACHE"); err == nil {
		if mc := strings.TrimSpace(string(out)); mc != "" {
			return mc
		}
	}
	return ""
}

func canonicalRealPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved), nil
	}
	return filepath.Clean(abs), nil
}

func isPathWithinDir(baseDir, target string) bool {
	if baseDir == "" || target == "" {
		return false
	}
	rel, err := filepath.Rel(baseDir, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func safeResolveWithin(baseDir, relSlash string) (string, error) {
	if baseDir == "" || relSlash == "" || strings.HasPrefix(relSlash, "/") || strings.Contains(relSlash, `\`) {
		return "", fmt.Errorf("invalid include path %q", relSlash)
	}
	cleanRel := filepath.Clean(filepath.FromSlash(relSlash))
	if cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanRel) {
		return "", fmt.Errorf("include path %q escapes base directory", relSlash)
	}
	candidate := filepath.Join(baseDir, cleanRel)
	if !isPathWithinDir(baseDir, candidate) {
		return "", fmt.Errorf("include path %q escapes %q", relSlash, baseDir)
	}
	resolvedBase, err := canonicalRealPath(baseDir)
	if err != nil {
		return "", err
	}
	resolvedCand, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	if !isPathWithinDir(resolvedBase, filepath.Clean(resolvedCand)) {
		return "", fmt.Errorf("include symlink %q escapes %q", relSlash, baseDir)
	}
	return filepath.Clean(resolvedCand), nil
}

func escapeGoModulePath(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (s *GoAMD64FrameSource) readConfinedInclude(pkg GoPackage, name string, recordHash bool) (string, []byte, error) {
	includeDir := filepath.Join(s.goroot, "pkg", "include")
	for _, dir := range []string{s.directory, includeDir} {
		candidate, err := safeResolveWithin(dir, name)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(candidate)
		if err == nil {
			if recordHash {
				s.snapshots[candidate] = sha256.Sum256(data)
			}
			return candidate, data, nil
		}
	}
	if name == "go_asm.h" && pkg.Types != nil {
		data, err := GoAssemblyHeader(pkg, "amd64")
		if err == nil {
			return filepath.Join(s.directory, "go_asm.h"), data, nil
		}
	}
	return "", nil, fmt.Errorf("include %q not found within allowed directories", name)
}

func (s *GoAMD64FrameSource) snapshotIncludedHeaders(pkg GoPackage) error {
	envMap := map[string]string{"GOOS": s.goos, "GOARCH": s.goarch}
	for _, kv := range s.environment {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = v
		}
	}
	defines := preprocess.GoAssemblerDefinesWithEnv(s.goos, s.goarch, envMap)
	_, err := preprocess.PreprocessAssemblySource(string(s.asmBytes), preprocess.AssemblyPreprocessOptions{
		FileName: filepath.Join(s.directory, s.assemblyFile),
		Defines:  defines,
		ReadInclude: func(_ string, name string) (string, []byte, error) {
			return s.readConfinedInclude(pkg, name, true)
		},
	})
	if err != nil {
		// Allow capture when go_asm.h or conditional headers are unavailable before
		// BindFixedLocal; BindFixedLocal performs the strict match check.
		return nil
	}
	return nil
}

// Verify checks that the source owner has not been closed and that no captured
// Go/assembly/header file (including resolved includes) has changed since capture.
func (s *GoAMD64FrameSource) Verify(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("%w: nil AMD64 frame source", ErrProbeNeedsContext)
	}
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("%w: %v", ErrProbeNeedsContext, ctx.Err())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%w: AMD64 frame source lease has been revoked", ErrProbeNeedsContext)
	}
	for fullPath, want := range s.snapshots {
		data, err := os.ReadFile(fullPath)
		if err != nil {
			s.closed = true
			return fmt.Errorf("%w: captured source %q disappeared: %v", ErrProbeNeedsContext, fullPath, err)
		}
		if sha256.Sum256(data) != want {
			s.closed = true
			return fmt.Errorf("%w: captured source %q changed during frame lifetime", ErrProbeNeedsContext, fullPath)
		}
	}
	return nil
}

// Close revokes the frame source lease so any previously bound signatures can
// no longer authorize physical-frame translation.
func (s *GoAMD64FrameSource) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

// BindFixedLocal verifies that file matches the captured source expansion,
// checks ABI0 register initialization & SP confinement, derives outgoing ABI0
// signatures for SDK runtime callees (such as runtime.memmove), and attaches a
// live lease hook to each bound signature.
func (s *GoAMD64FrameSource) BindFixedLocal(ctx context.Context, pkg GoPackage, file *File, opt Options) (Options, error) {
	if err := s.Verify(ctx); err != nil {
		return Options{}, err
	}
	if file == nil || file.Arch != ArchAMD64 {
		return Options{}, fmt.Errorf("%w: AMD64 physical frame binding requires an AMD64 file", ErrProbeNeedsContext)
	}
	// Preprocess the captured on-disk assembly file with the selected SDK's
	// pkg/include and verify the parsed functions match file exactly (rejects
	// altered/spoofed preprocessed expansions).
	if err := s.verifyCapturedFileMatches(pkg, file); err != nil {
		return Options{}, err
	}

	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(sym string) string { return goStripABISuffix(sym) }
	}
	out := opt
	out.Sigs = make(map[string]FuncSig, len(opt.Sigs))
	for k, v := range opt.Sigs {
		out.Sigs[k] = v
	}

	leaseCheck := func() error { return s.Verify(context.Background()) }

	for _, fn := range file.Funcs {
		name := resolve(goTextSymbolForResolution(fn.Sym))
		sig, ok := out.Sigs[name]
		if !ok {
			return Options{}, fmt.Errorf("%w: missing caller signature for physical frame function %q", ErrProbeNeedsContext, name)
		}
		// Verify register initialization, private SP confinement, and result init.
		if _, err := x86.CheckABI0ResultInit(fn, sig, "amd64"); err != nil {
			return Options{}, err
		}
		// Resolve outgoing ABI0 CALL targets (e.g. runtime·memmove(SB)).
		for _, ins := range fn.Instrs {
			if strings.ToUpper(string(ins.Op)) != "CALL" || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				continue
			}
			rawSym := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
			callee := resolve(goStripABISuffix(rawSym))
			if _, exists := out.Sigs[callee]; exists {
				continue
			}
			csig, err := s.deriveSDKCalleeABI0Sig(pkg, callee)
			if err != nil {
				return Options{}, fmt.Errorf("%w: unresolved outgoing ABI0 callee %q: %v", ErrProbeNeedsContext, callee, err)
			}
			csig.FrameLease = leaseCheck
			out.Sigs[callee] = csig
		}
		sig.FrameLease = leaseCheck
		out.Sigs[name] = sig
	}
	return out, nil
}

func (s *GoAMD64FrameSource) verifyCapturedFileMatches(pkg GoPackage, file *File) error {
	readInclude := func(_ string, name string) (string, []byte, error) {
		return s.readConfinedInclude(pkg, name, false)
	}
	envMap := map[string]string{"GOOS": s.goos, "GOARCH": s.goarch}
	for _, kv := range s.environment {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = v
		}
	}
	defines := preprocess.GoAssemblerDefinesWithEnv(s.goos, s.goarch, envMap)
	expanded, err := preprocess.PreprocessAssemblySource(string(s.asmBytes), preprocess.AssemblyPreprocessOptions{
		FileName:    filepath.Join(s.directory, s.assemblyFile),
		Defines:     defines,
		ReadInclude: readInclude,
	})
	if err != nil {
		return fmt.Errorf("%w: captured assembly preprocess failed: %v", ErrProbeNeedsContext, err)
	}
	captured, err := Parse(ArchAMD64, expanded)
	if err != nil {
		return fmt.Errorf("%w: captured assembly parse failed: %v", ErrProbeNeedsContext, err)
	}
	if len(captured.Funcs) != len(file.Funcs) {
		return fmt.Errorf("%w: preprocessed assembly function count differs from captured source", ErrProbeNeedsContext)
	}
	for i := range captured.Funcs {
		cf, ff := captured.Funcs[i], file.Funcs[i]
		if cf.Sym != ff.Sym || cf.FrameSize != ff.FrameSize || cf.ArgSize != ff.ArgSize || len(cf.Instrs) != len(ff.Instrs) {
			return fmt.Errorf("%w: preprocessed assembly differs from captured source in %s", ErrProbeNeedsContext, cf.Sym)
		}
		for j := range cf.Instrs {
			ci, fi := cf.Instrs[j], ff.Instrs[j]
			if ci.Op != fi.Op || len(ci.Args) != len(fi.Args) {
				return fmt.Errorf("%w: preprocessed instruction differs from captured source at %s[%d]", ErrProbeNeedsContext, cf.Sym, j)
			}
			for k := range ci.Args {
				if ci.Args[k].String() != fi.Args[k].String() {
					return fmt.Errorf("%w: preprocessed operand differs from captured source at %s[%d]", ErrProbeNeedsContext, cf.Sym, j)
				}
			}
		}
	}
	return nil
}

// deriveSDKCalleeABI0Sig derives the exact ABI0 signature of an external SDK
// callee (such as runtime.memmove) from package imports or the selected GOROOT.
func (s *GoAMD64FrameSource) deriveSDKCalleeABI0Sig(pkg GoPackage, callee string) (FuncSig, error) {
	dot := strings.LastIndexByte(callee, '.')
	if dot <= 0 || dot == len(callee)-1 {
		return FuncSig{}, fmt.Errorf("invalid callee symbol %q", callee)
	}
	pkgPath, funcName := callee[:dot], callee[dot+1:]
	sizes := types.SizesFor("gc", "amd64")

	// 1. Check already-loaded package imports first.
	if imp, ok := pkg.Imports[pkgPath]; ok && imp != nil && imp.Scope() != nil {
		if fn, ok := imp.Scope().Lookup(funcName).(*types.Func); ok {
			return DeriveGoFuncABI0Signature(callee, fn, "amd64", sizes)
		}
	}

	// 2. Inspect actual SDK source declarations in GOROOT/src/<pkgPath>
	// matching the target (GOOS, GOARCH) build constraints.
	srcDir := filepath.Join(s.goroot, "src", filepath.FromSlash(pkgPath))
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return FuncSig{}, err
	}
	bctx := build.Default
	bctx.GOOS = s.goos
	bctx.GOARCH = s.goarch
	bctx.GOROOT = s.goroot
	bctx.CgoEnabled = false
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		if match, merr := bctx.MatchFile(srcDir, entry.Name()); merr != nil || !match {
			continue
		}
		parsed, err := parser.ParseFile(fset, filepath.Join(srcDir, entry.Name()), nil, 0)
		if err != nil {
			continue
		}
		for _, d := range parsed.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Name.Name != funcName {
				continue
			}
			if sig, ok := deriveSimpleABI0SigFromAST(callee, fd.Type); ok {
				return sig, nil
			}
		}
	}
	return FuncSig{}, fmt.Errorf("declaration %s not found in SDK %s", callee, s.goroot)
}

func deriveSimpleABI0SigFromAST(name string, ft *ast.FuncType) (FuncSig, bool) {
	if ft == nil {
		return FuncSig{}, false
	}
	astTypeToLLVM := func(expr ast.Expr) (LLVMType, int64, bool) {
		switch t := expr.(type) {
		case *ast.StarExpr:
			return Ptr, 8, true
		case *ast.SelectorExpr:
			if id, ok := t.X.(*ast.Ident); ok && id.Name == "unsafe" && t.Sel.Name == "Pointer" {
				return Ptr, 8, true
			}
		case *ast.Ident:
			switch t.Name {
			case "uintptr", "uint64", "int64", "int", "uint":
				return I64, 8, true
			case "uint32", "int32":
				return I32, 4, true
			case "uint16", "int16":
				return I16, 2, true
			case "uint8", "byte", "int8":
				return I8, 1, true
			case "bool":
				return I1, 1, true
			}
		}
		return "", 0, false
	}
	var args []LLVMType
	var params []FrameSlot
	var off int64
	if ft.Params != nil {
		for _, field := range ft.Params.List {
			ty, sz, ok := astTypeToLLVM(field.Type)
			if !ok {
				return FuncSig{}, false
			}
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				off = goAlignOff(off, sz)
				params = append(params, FrameSlot{Offset: off, Type: ty, Index: len(args), Field: -1})
				args = append(args, ty)
				off += sz
			}
		}
	}
	off = goAlignOff(off, 8)
	var rets []LLVMType
	var results []FrameSlot
	if ft.Results != nil {
		for _, field := range ft.Results.List {
			ty, sz, ok := astTypeToLLVM(field.Type)
			if !ok {
				return FuncSig{}, false
			}
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				off = goAlignOff(off, sz)
				results = append(results, FrameSlot{Offset: off, Type: ty, Index: len(rets), Field: -1})
				rets = append(rets, ty)
				off += sz
			}
		}
	}
	return FuncSig{
		Name:  name,
		Args:  args,
		Ret:   goTupleRetType(rets),
		Frame: FrameLayout{Params: params, Results: results},
	}, true
}

func funcUsesPhysicalAMD64SP(fn Func) bool {
	if fn.FrameSize <= 0 {
		return false
	}
	for _, ins := range fn.Instrs {
		for _, arg := range ins.Args {
			if arg.Kind == OpMem && arg.Mem.Base == SP && arg.Mem.Off >= 0 {
				return true
			}
		}
	}
	return false
}

var _ = asm.ArchAMD64
