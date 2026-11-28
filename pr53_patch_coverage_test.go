package plan9asm

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type testImporterFunc func(path string) (*types.Package, error)

func (f testImporterFunc) Import(path string) (*types.Package, error) { return f(path) }

func TestPR53GoAssemblyHeaderEdgeCases(t *testing.T) {
	if _, err := GoAssemblyHeader(GoPackage{}, "amd64"); err == nil {
		t.Fatalf("expected error for nil package types")
	}
	src := `package hdr
const (
	_ = 1
	IntVal = 42
	FloatVal = 3.14
	CmpVal = 1 + 2i
)
type Plain int
type Gen[T any] struct {
	V T
	A [2]T
	S []T
	P *T
	M map[string]T
	C chan T
}
type Concrete struct {
	_ uint32
	X uint64
}
type WrapConcrete struct {
	G Gen[int]
}
`
	pkg := mustGoPackage(t, "example.com/hdr", src)
	if _, err := GoAssemblyHeader(pkg, "unknownarch"); err == nil {
		t.Fatalf("expected error for unknown goarch")
	}
	hdrBytes, err := GoAssemblyHeader(pkg, "amd64")
	if err != nil {
		t.Fatalf("GoAssemblyHeader: %v", err)
	}
	hdr := string(hdrBytes)
	if !strings.Contains(hdr, "#define const_IntVal 42") ||
		strings.Contains(hdr, "FloatVal") ||
		strings.Contains(hdr, "CmpVal") ||
		strings.Contains(hdr, "Gen__size") ||
		!strings.Contains(hdr, "#define Concrete_X 8") ||
		!strings.Contains(hdr, "#define WrapConcrete__size") {
		t.Fatalf("unexpected go_asm.h:\n%s", hdr)
	}
	// Exercise goTypeHasUnboundTypeParams across nested container types.
	genObj := pkg.Types.Scope().Lookup("Gen").Type()
	if !goTypeHasUnboundTypeParams(genObj) {
		t.Fatalf("expected Gen to have unbound type params")
	}
	if !goTypeHasUnboundTypeParams(types.NewSlice(genObj)) ||
		!goTypeHasUnboundTypeParams(types.NewPointer(genObj)) ||
		!goTypeHasUnboundTypeParams(types.NewArray(genObj, 2)) ||
		!goTypeHasUnboundTypeParams(types.NewMap(types.Typ[types.String], genObj)) ||
		!goTypeHasUnboundTypeParams(types.NewChan(types.SendRecv, genObj)) {
		t.Fatalf("expected container of Gen to report unbound type params")
	}
}

func TestPR53GoAMD64FrameSourceDeepCoverage(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not found")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	goSrc := `package p
type Pair struct { Lo, Hi uint64 }
func Copy(dst, src *byte, n uintptr) uint64
`
	asmSrc := `#include "go_asm.h"
TEXT ·Copy(SB),NOSPLIT,$32-32
	MOVQ dst+0(FP), AX
	MOVQ AX, 0(SP)
	MOVQ src+8(FP), BX
	MOVQ BX, 8(SP)
	MOVQ n+16(FP), CX
	MOVQ CX, 16(SP)
	CALL runtime·memmove(SB)
	MOVQ $Pair__size, AX
	MOVQ AX, ret+24(FP)
	RET
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/p\ngo 1.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(goSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p_amd64.s"), []byte(asmSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "example.com/p", goSrc)
	ctx := context.Background()

	// Exercise error branches in CaptureGoAMD64*FrameSource.
	if _, err := CaptureGoAMD64FrameSource(nil, pkg, GoAMD64FrameCaptureRequest{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on nil ctx, got %v", err)
	}
	if _, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{Target: "linux/arm64"}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on non-amd64 target, got %v", err)
	}
	if _, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{Target: "linux/amd64"}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on incomplete request, got %v", err)
	}
	if _, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     "/nonexistent-go-binary",
		Directory:    dir,
		AssemblyFile: "p_amd64.s",
		Target:       "linux/amd64",
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on invalid go binary, got %v", err)
	}
	if _, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     goBin,
		Directory:    filepath.Join(dir, "missing"),
		AssemblyFile: "p_amd64.s",
		Target:       "linux/amd64",
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on missing dir, got %v", err)
	}
	if _, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     goBin,
		Directory:    dir,
		AssemblyFile: "nope.s",
		Target:       "linux/amd64",
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on missing asm file, got %v", err)
	}
	if _, err := CaptureGoAMD64DownloadedFrameSource(ctx, pkg, GoAMD64DownloadedFrameCaptureRequest{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on empty downloaded frame source")
	}

	// SDK capture must reject directories outside GOROOT/src, and succeed on a real SDK directory
	// (also verifying GOROOT resolution via `go env GOROOT` when GOROOT is absent from env).
	if _, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     goBin,
		Directory:    dir,
		AssemblyFile: "p_amd64.s",
		Target:       "linux/amd64",
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on SDK capture outside GOROOT/src, got %v", err)
	}
	sdkDir := filepath.Join(runtime.GOROOT(), "src", "internal", "bytealg")
	if entries, rerr := os.ReadDir(sdkDir); rerr == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), "_amd64.s") {
				sdkFS, serr := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
					GoBinary:     "go",
					Directory:    sdkDir,
					AssemblyFile: e.Name(),
					Target:       "linux/amd64",
					Environment:  filterOutEnv(os.Environ(), "GOROOT"),
				})
				if serr != nil {
					t.Fatalf("CaptureGoAMD64SDKFrameSource(%s): %v", e.Name(), serr)
				}
				sdkFS.Close()
				break
			}
		}
	}

	// Downloaded capture must reject directories outside GOMODCACHE/<escapedMod>@<ver>,
	// and succeed inside a properly structured module cache directory (testing uppercase escaping too).
	if _, err := CaptureGoAMD64DownloadedFrameSource(ctx, pkg, GoAMD64DownloadedFrameCaptureRequest{
		Original: GoAMD64FrameCaptureRequest{
			GoBinary:     goBin,
			Directory:    dir,
			AssemblyFile: "p_amd64.s",
			Target:       "linux/amd64",
			Environment:  append(os.Environ(), "GOROOT="+runtime.GOROOT()),
		},
		SourceModule:  "example.com/P",
		SourceVersion: "v1.0.0",
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on downloaded capture outside GOMODCACHE, got %v", err)
	}

	modCache := t.TempDir()
	modDir := filepath.Join(modCache, "example.com", "!p@v1.0.0")
	if err := os.MkdirAll(filepath.Join(modDir, "inc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "p.go"), []byte(goSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "inc", "defs.h"), []byte("#define MY_OFF 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	incAsm := "#include \"inc/defs.h\"\n" + asmSrc
	if err := os.WriteFile(filepath.Join(modDir, "p_amd64.s"), []byte(incAsm), 0o600); err != nil {
		t.Fatal(err)
	}
	dlEnv := append(filterOutEnv(os.Environ(), "GOMODCACHE"), "GOROOT="+runtime.GOROOT(), "GOMODCACHE="+modCache)
	dlFS, err := CaptureGoAMD64DownloadedFrameSource(ctx, pkg, GoAMD64DownloadedFrameCaptureRequest{
		Original: GoAMD64FrameCaptureRequest{
			GoBinary:     goBin,
			Directory:    modDir,
			AssemblyFile: "p_amd64.s",
			Target:       "linux/amd64",
			Environment:  dlEnv,
		},
		SourceModule:  "example.com/P",
		SourceVersion: "v1.0.0",
	})
	if err != nil {
		t.Fatalf("CaptureGoAMD64DownloadedFrameSource: %v", err)
	}
	defer dlFS.Close()

	// Verify included header tampering after capture is detected by Verify.
	tamperModDir := filepath.Join(modCache, "example.com", "tamper@v1.0.0")
	if err := os.MkdirAll(filepath.Join(tamperModDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tamperModDir, "p.go"), []byte(goSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	hdrPath := filepath.Join(tamperModDir, "sub", "defs.h")
	if err := os.WriteFile(hdrPath, []byte("#define K 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tamperModDir, "p_amd64.s"), []byte("#include \"sub/defs.h\"\nTEXT ·Copy(SB),NOSPLIT,$0-0\n\tRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tFS, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     goBin,
		Directory:    tamperModDir,
		AssemblyFile: "p_amd64.s",
		Target:       "linux/amd64",
		Environment:  dlEnv,
	})
	if err != nil {
		t.Fatalf("capture tamperModDir: %v", err)
	}
	if err := os.WriteFile(hdrPath, []byte("#define K 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tFS.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected Verify error after editing included header, got %v", err)
	}
	tFS.Close()

	// Verify path traversal, escaping symlinks, invalid assembly names, and GOPATH/env modcache helpers.
	if _, err := safeResolveWithin(modDir, "../escape.h"); err == nil {
		t.Fatalf("expected safeResolveWithin to reject ../escape.h")
	}
	if _, err := safeResolveWithin(modDir, "/etc/passwd"); err == nil {
		t.Fatalf("expected safeResolveWithin to reject absolute path")
	}
	outsideFile := filepath.Join(t.TempDir(), "secret.h")
	if err := os.WriteFile(outsideFile, []byte("#define SECRET 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(modDir, "escape_link.h")
	if err := os.Symlink(outsideFile, linkPath); err == nil {
		if _, err := safeResolveWithin(modDir, "escape_link.h"); err == nil {
			t.Fatalf("expected safeResolveWithin to reject escaping symlink")
		}
		_ = os.Remove(linkPath)
	}
	if _, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     goBin,
		Directory:    dir,
		AssemblyFile: "../bad.s",
		Target:       "linux/amd64",
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on invalid assembly filename, got %v", err)
	}
	if got := resolveAMD64FrameModCache(ctx, dir, []string{"GOPATH=" + modCache}, goBin); got != filepath.Join(modCache, "pkg", "mod") {
		t.Fatalf("resolveAMD64FrameModCache(GOPATH) = %q", got)
	}
	if got := resolveAMD64FrameModCache(ctx, dir, filterOutEnv(filterOutEnv(os.Environ(), "GOMODCACHE"), "GOPATH"), goBin); got == "" {
		t.Fatalf("expected non-empty GOMODCACHE from go env")
	}

	// Verify nil receiver & canceled context handling.
	var nilFS *GoAMD64FrameSource
	if err := nilFS.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on nil Verify, got %v", err)
	}
	if err := nilFS.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := dlFS.Verify(cctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on canceled Verify, got %v", err)
	}

	// Preprocess & parse matching source, then exercise BindFixedLocal + runtime.memmove SDK derivation!
	expanded := strings.ReplaceAll(asmSrc, `#include "go_asm.h"`, "")
	expanded = strings.ReplaceAll(expanded, "$Pair__size", "$16")
	parsed, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	copyFn := pkg.Types.Scope().Lookup("Copy").(*types.Func)
	copySig, err := DeriveGoFuncABI0Signature("example.com/p.Copy", copyFn, "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}

	// BindFixedLocal error paths: nil file, mismatched func count, mismatched frame, mismatched op, mismatched operand, missing sig.
	if _, err := dlFS.BindFixedLocal(ctx, pkg, nil, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on nil file, got %v", err)
	}
	emptyFile, _ := Parse(ArchAMD64, "")
	if _, err := dlFS.BindFixedLocal(ctx, pkg, emptyFile, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on func count mismatch, got %v", err)
	}
	badFrame, _ := Parse(ArchAMD64, strings.Replace(expanded, "$32-32", "$40-32", 1))
	if _, err := dlFS.BindFixedLocal(ctx, pkg, badFrame, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on frame mismatch, got %v", err)
	}
	badOp, _ := Parse(ArchAMD64, strings.Replace(expanded, "MOVQ dst+0(FP), AX", "ADDQ dst+0(FP), AX", 1))
	if _, err := dlFS.BindFixedLocal(ctx, pkg, badOp, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on op mismatch, got %v", err)
	}
	badArg, _ := Parse(ArchAMD64, strings.Replace(expanded, "$16, AX", "$32, AX", 1))
	if _, err := dlFS.BindFixedLocal(ctx, pkg, badArg, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on arg mismatch, got %v", err)
	}
	if _, err := dlFS.BindFixedLocal(ctx, pkg, parsed, Options{Goarch: "amd64"}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected error on missing caller sig, got %v", err)
	}

	// Successful BindFixedLocal resolving runtime.memmove from GOROOT/src/runtime!
	bound, err := dlFS.BindFixedLocal(ctx, pkg, parsed, Options{
		Goarch:     "amd64",
		ResolveSym: testResolveSym("example.com/p"),
		Sigs:       map[string]FuncSig{"example.com/p.Copy": copySig},
	})
	if err != nil {
		t.Fatalf("BindFixedLocal with runtime.memmove: %v", err)
	}
	if _, ok := bound.Sigs["runtime.memmove"]; !ok {
		t.Fatalf("expected runtime.memmove signature to be derived, got %+v", bound.Sigs)
	}
	if err := validateAMD64PhysicalFrameLeases(parsed, testResolveSym("example.com/p"), bound.Sigs); err != nil {
		t.Fatalf("validateAMD64PhysicalFrameLeases live: %v", err)
	}

	// Also exercise deriveSDKCalleeABI0Sig via pkg.Imports & error paths.
	depPkg := mustGoPackage(t, "example.com/dep", "package dep\nfunc Helper(a uint64) uint32\n")
	pkgWithImp := pkg
	pkgWithImp.Imports = map[string]*types.Package{"example.com/dep": depPkg.Types}
	if sig, err := dlFS.deriveSDKCalleeABI0Sig(pkgWithImp, "example.com/dep.Helper"); err != nil || sig.Ret != I32 {
		t.Fatalf("deriveSDKCalleeABI0Sig import: sig=%+v err=%v", sig, err)
	}
	if _, err := dlFS.deriveSDKCalleeABI0Sig(pkg, "badname"); err == nil {
		t.Fatalf("expected invalid callee error")
	}
	if _, err := dlFS.deriveSDKCalleeABI0Sig(pkg, "nosuch/pkg.Fn"); err == nil {
		t.Fatalf("expected missing pkg error")
	}
	if _, err := dlFS.deriveSDKCalleeABI0Sig(pkg, "runtime.NoSuchFunctionXYZ"); err == nil {
		t.Fatalf("expected missing decl error")
	}

	// Exercise deriveSimpleABI0SigFromAST across all scalar types & error cases.
	if _, ok := deriveSimpleABI0SigFromAST("nil", nil); ok {
		t.Fatalf("expected false for nil FuncType")
	}
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "f.go", `package x
import "unsafe"
func All(p *byte, u unsafe.Pointer, a, b uint64, c uint32, d uint16, e byte, f bool) (r1 int32, r2, r3 bool)
func BadParam(x float64)
func BadRet() float64
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range af.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		sig, ok := deriveSimpleABI0SigFromAST("x."+fd.Name.Name, fd.Type)
		switch fd.Name.Name {
		case "All":
			if !ok || len(sig.Args) != 8 || len(sig.Frame.Results) != 3 {
				t.Fatalf("All sig unexpected: ok=%v sig=%+v", ok, sig)
			}
		case "BadParam", "BadRet":
			if ok {
				t.Fatalf("expected %s to fail AST derivation", fd.Name.Name)
			}
		}
	}

	// Modify captured file on disk -> Verify detects tampering & revokes lease.
	if err := os.WriteFile(filepath.Join(modDir, "p.go"), []byte(goSrc+"\n// edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := dlFS.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected tampering error, got %v", err)
	}
	if err := validateAMD64PhysicalFrameLeases(parsed, testResolveSym("example.com/p"), bound.Sigs); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected revoked lease error, got %v", err)
	}

	// Delete captured file on disk -> Verify detects disappearance.
	fs2, err := CaptureGoAMD64FrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     goBin,
		Directory:    dir,
		AssemblyFile: "p_amd64.s",
		Target:       "linux/amd64",
		Environment:  append(os.Environ(), "GOROOT="+runtime.GOROOT()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "p.go")); err != nil {
		t.Fatal(err)
	}
	if err := fs2.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected disappeared file error, got %v", err)
	}

	// funcUsesPhysicalAMD64SP returns false when FrameSize > 0 without SP mem access.
	noSP, _ := Parse(ArchAMD64, "TEXT ·NoSP(SB),NOSPLIT,$16-0\n\tMOVQ $1, AX\n\tRET\n")
	if funcUsesPhysicalAMD64SP(noSP.Funcs[0]) {
		t.Fatalf("expected funcUsesPhysicalAMD64SP=false")
	}
}

func TestPR53GoTranslateValidationAndImportedGlobals(t *testing.T) {
	// 1. validatePreprocessedResolvedImmediates & DeriveGoFuncABI0Signature errors.
	if err := validatePreprocessedResolvedImmediates(nil); err != nil {
		t.Fatalf("nil file: %v", err)
	}
	if _, err := DeriveGoFuncABI0Signature("", nil, "amd64", nil); err == nil {
		t.Fatalf("expected error on nil fn")
	}
	badFn := types.NewFunc(token.NoPos, nil, "bad", nil)
	if _, err := DeriveGoFuncABI0Signature("bad", badFn, "amd64", nil); err == nil {
		t.Fatalf("expected error on nil signature")
	}

	// 2. Imported global verification + astTypeMatchesGoType across all Go types.
	depSrc := `package dep
import "unsafe"
type Named struct { A int; B byte }
type AliasInt = int
var (
	VInt int
	VByte byte
	VRune rune
	VNamed Named
	VAny any
	VAlias AliasInt
	VPtr *int
	VUnsafe unsafe.Pointer
	VSlice []byte
	VArr [4]uint64
	VStruct struct { A int; B byte }
	VMap map[string]int
	VChan chan int
	VIface interface{ M() }
	VFunc func()
	VParen (int)
)
`
	fset := token.NewFileSet()
	depFile, err := parser.ParseFile(fset, "dep.go", depSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	depTypes, err := (&types.Config{Importer: nil}).Check("example.com/dep", fset, []*ast.File{depFile}, nil)
	// unsafe import needs default importer; use a custom importer for unsafe only.
	if err != nil {
		imp := testImporterFunc(func(path string) (*types.Package, error) {
			if path == "unsafe" {
				return types.Unsafe, nil
			}
			return nil, errors.New("not found")
		})
		depTypes, err = (&types.Config{Importer: imp}).Check("example.com/dep", fset, []*ast.File{depFile}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	mainSrc := `package main
import _ "example.com/dep"
func Load() uint64
`
	mainFile, err := parser.ParseFile(fset, "main.go", mainSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	imp := testImporterFunc(func(path string) (*types.Package, error) {
		if path == "example.com/dep" {
			return depTypes, nil
		}
		if path == "unsafe" {
			return types.Unsafe, nil
		}
		return nil, errors.New("not found")
	})
	mainTypes, err := (&types.Config{Importer: imp}).Check("example.com/main", fset, []*ast.File{mainFile}, nil)
	if err != nil {
		t.Fatal(err)
	}

	asmSrc := `TEXT ·Load(SB),NOSPLIT,$0-8
	MOVQ example.com∕dep·VInt(SB), AX
	MOVQ AX, ret+0(FP)
	RET
`
	res := func(sym string) string {
		sym = strings.ReplaceAll(sym, "∕", "/")
		if strings.HasPrefix(sym, "·") {
			return "example.com/main." + strings.TrimPrefix(sym, "·")
		}
		return strings.ReplaceAll(sym, "·", ".")
	}
	// Missing pkg.Imports -> ErrProbeNeedsContext
	pkg := GoPackage{Path: "example.com/main", Types: mainTypes, Syntax: []*ast.File{mainFile}}
	if _, err := TranslateGoModule(pkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: res,
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected ErrProbeNeedsContext for missing Imports, got %v", err)
	}
	// Missing pkg.ImportSyntax entry -> ErrProbeNeedsContext
	pkg.Imports = map[string]*types.Package{"example.com/dep": depTypes}
	pkg.ImportSyntax = map[string][]*ast.File{}
	if _, err := TranslateGoModule(pkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: res,
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected ErrProbeNeedsContext for missing ImportSyntax, got %v", err)
	}
	// Mismatched syntax type -> ErrProbeNeedsContext
	badDepFile, _ := parser.ParseFile(fset, "bad.go", "package dep\nvar VInt string\n", 0)
	pkg.ImportSyntax = map[string][]*ast.File{"example.com/dep": {badDepFile}}
	if _, err := TranslateGoModule(pkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: res,
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected ErrProbeNeedsContext for mismatched var type, got %v", err)
	}
	// Missing var in syntax -> ErrProbeNeedsContext
	emptyDepFile, _ := parser.ParseFile(fset, "empty.go", "package dep\n", 0)
	pkg.ImportSyntax = map[string][]*ast.File{"example.com/dep": {emptyDepFile}}
	if _, err := TranslateGoModule(pkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: res,
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected ErrProbeNeedsContext for missing var in syntax, got %v", err)
	}
	// Matching syntax -> succeeds!
	pkg.ImportSyntax = map[string][]*ast.File{"example.com/dep": {depFile}}
	tr, err := TranslateGoModule(pkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: res,
	})
	if err != nil {
		t.Fatalf("TranslateGoModule valid imported global: %v", err)
	}
	tr.Module.Dispose()

	// Directly exercise verifyImportedVarSyntax & astTypeMatchesGoType on all dep vars!
	for _, name := range []string{
		"VInt", "VByte", "VRune", "VNamed", "VAny", "VPtr",
		"VUnsafe", "VSlice", "VArr", "VStruct", "VMap", "VChan", "VIface", "VFunc", "VParen",
	} {
		v := depTypes.Scope().Lookup(name).(*types.Var)
		if err := verifyImportedVarSyntax([]*ast.File{nil, depFile}, name, v.Type(), depTypes); err != nil {
			t.Fatalf("verifyImportedVarSyntax(%s): %v", name, err)
		}
	}
	intExpr, _ := parser.ParseExpr("int")
	if !astTypeMatchesGoType(intExpr, depTypes.Scope().Lookup("VAlias").Type(), depTypes) {
		t.Fatalf("expected int expr to match AliasInt")
	}
	// Exercise astTypeMatchesGoType negative branches & selector/array/struct checks.
	if astTypeMatchesGoType(nil, types.Typ[types.Int], depTypes) {
		t.Fatalf("expected nil expr false")
	}
	if astTypeMatchesGoType(&ast.BasicLit{}, types.Typ[types.Int], depTypes) {
		t.Fatalf("expected default expr false")
	}
	wrongArrExpr, _ := parser.ParseExpr("[5]uint64")
	if astTypeMatchesGoType(wrongArrExpr, depTypes.Scope().Lookup("VArr").Type(), depTypes) {
		t.Fatalf("expected wrong array len false")
	}
	wrongStructExpr, _ := parser.ParseExpr("struct{ A int; C byte }")
	if astTypeMatchesGoType(wrongStructExpr, depTypes.Scope().Lookup("VStruct").Type(), depTypes) {
		t.Fatalf("expected wrong struct field name false")
	}
	extraFieldExpr, _ := parser.ParseExpr("struct{ A int; B byte; C int }")
	if astTypeMatchesGoType(extraFieldExpr, depTypes.Scope().Lookup("VStruct").Type(), depTypes) {
		t.Fatalf("expected extra struct field false")
	}
	selNamedExpr, _ := parser.ParseExpr("dep.Named")
	if !astTypeMatchesGoType(selNamedExpr, depTypes.Scope().Lookup("VNamed").Type(), depTypes) {
		t.Fatalf("expected selector named match")
	}
	selAliasExpr, _ := parser.ParseExpr("dep.AliasInt")
	if astTypeMatchesGoType(selAliasExpr, depTypes.Scope().Lookup("VAlias").Type(), depTypes) {
		t.Fatalf("expected selector basic alias mismatch")
	}

	// 3. Closure context validation & unresolved immediate errors in TranslateGoModule.
	closurePkg := mustGoPackage(t, "example.com/c", "package c\nfunc F() uint64\n")
	if _, err := TranslateGoModule(closurePkg, []byte("TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVQ 0(DX), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: testResolveSym("example.com/c"),
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected ErrProbeNeedsContext on uninitialized DX closure load, got %v", err)
	}
	if _, err := TranslateGoModule(closurePkg, []byte("TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVQ $UNRESOLVED_CONST, AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: testResolveSym("example.com/c"),
	}); err == nil {
		t.Fatalf("expected error on unresolved symbolic immediate")
	}
	if _, err := TranslateGoModule(closurePkg, []byte("TEXT ·F(SB),NOSPLIT,$0-8\n\tBAD SYNTAX (((\n"), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "amd64", ResolveSym: testResolveSym("example.com/c"),
	}); err == nil {
		t.Fatalf("expected parse error")
	}
	// Exercise funcWritesReg branches (DL, CMPQ, XCHGQ, LDP).
	for _, snippet := range []string{
		"TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVB $1, DL\n\tMOVQ 0(DX), AX\n\tRET\n",
		"TEXT ·F(SB),NOSPLIT,$0-8\n\tXCHGQ AX, DX\n\tMOVQ 0(DX), AX\n\tRET\n",
		"TEXT ·F(SB),NOSPLIT,$0-8\n\tCMPQ AX, DX\n\tRET\n",
	} {
		pf, err := Parse(ArchAMD64, snippet)
		if err != nil {
			t.Fatal(err)
		}
		_ = funcWritesReg(pf.Funcs[0], "amd64", DX)
	}
	arm64Ldp, _ := Parse(ArchARM64, "TEXT ·F(SB),NOSPLIT,$0-0\n\tLDP (R0), (R1, R26)\n\tRET\n")
	if !funcWritesReg(arm64Ldp.Funcs[0], "arm64", Reg("R26")) {
		t.Fatalf("expected LDP to mark R26 written")
	}

	// 4. Nested array/complex frame parts.
	aggPkg := mustGoPackage(t, "example.com/agg", `package agg
type Nested struct {
	Arr [2]uint64
	S string
}
func Take(n Nested) (complex64, complex128)
`)
	takeFn := aggPkg.Types.Scope().Lookup("Take").(*types.Func)
	sig, err := DeriveGoFuncABI0Signature("example.com/agg.Take", takeFn, "amd64", types.SizesFor("gc", "amd64"))
	if err != nil || len(sig.Frame.Params) < 4 || len(sig.Frame.Results) != 4 {
		t.Fatalf("DeriveGoFuncABI0Signature nested: sig=%+v err=%v", sig, err)
	}
	if _, ok := goFramePartsForType(types.Typ[types.Complex64], "amd64"); !ok {
		t.Fatalf("expected complex64 frame parts")
	}
	if _, ok := goFramePartsForType(types.Typ[types.Complex128], "amd64"); !ok {
		t.Fatalf("expected complex128 frame parts")
	}

	// 5. validateAMD64PhysicalFrameLeases error branches (entersyscall skip, unknown callee, missing sig, ABI0 violation).
	spFile, _ := Parse(ArchAMD64, "TEXT ·F(SB),NOSPLIT,$16-8\n\tMOVQ $1, 0(SP)\n\tCALL runtime·entersyscall(SB)\n\tCALL runtime·unknownFn(SB)\n\tMOVQ $0, ret+0(FP)\n\tRET\n")
	if err := validateAMD64PhysicalFrameLeases(spFile, testResolveSym("example.com/c"), map[string]FuncSig{}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected missing sig error, got %v", err)
	}
	fSig := FuncSig{Name: "example.com/c.F", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}
	if err := validateAMD64PhysicalFrameLeases(spFile, testResolveSym("example.com/c"), map[string]FuncSig{"example.com/c.F": fSig}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected unknown callee error, got %v", err)
	}

	// 6. ARM64 file with a tail-calling root AND an unrelated unbound <> helper
	//    must still reject the unrelated unbound <> helper.
	orphanSrc := `
TEXT ·Entry(SB), NOSPLIT, $0-8
	MOVD a+0(FP), R0
	B helper<>(SB)

TEXT helper<>(SB), NOSPLIT, $0-0
	MOVD R0, R0
	RET

TEXT orphan<>(SB), NOSPLIT, $0-0
	RET
`
	orphanFile, err := Parse(ArchARM64, orphanSrc)
	if err != nil {
		t.Fatal(err)
	}
	orphanPkg := mustGoPackage(t, "example.com/a64", "package a64\nfunc Entry(a int64)\n")
	if _, err := goSigsForAsmFile(orphanPkg, orphanFile, testResolveSym("example.com/a64"), "arm64", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "missing signature for file-local assembly") {
		t.Fatalf("expected missing signature error for unbound orphan<>, got %v", err)
	}
}

func filterOutEnv(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return out
}

func TestPR53ARM64TailAndBranchAndARMFPEdges(t *testing.T) {
	// 1. arm64_tail.go edge cases.
	if GoARM64ABI0TailDeclarationBindingNeeded(nil) {
		t.Fatalf("nil file should not need tail binding")
	}
	if _, err := BindGoARM64ABI0TailDeclarations(GoPackage{}, nil, nil, nil); err != nil {
		t.Fatalf("nil BindGoARM64ABI0TailDeclarations: %v", err)
	}
	if !isARM64HelperSym("helper<>") || isARM64HelperSym("plain") {
		t.Fatalf("isARM64HelperSym mismatch")
	}
	if _, err := formatASTFile(nil, nil); err == nil {
		t.Fatalf("expected formatASTFile(nil, nil) error")
	}

	fset := token.NewFileSet()
	goSrc := "package p\nfunc Tail(x uint64) uint64\n"
	af, err := parser.ParseFile(fset, "p.go", goSrc, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	sizes := types.SizesFor("gc", "arm64")
	tpkg, err := (&types.Config{Sizes: sizes}).Check("example.com/p", fset, []*ast.File{af}, info)
	if err != nil {
		t.Fatal(err)
	}
	tailAsm := `TEXT ·Tail(SB),NOSPLIT,$0-16
	MOVD x+0(FP), R0
	MOVD $ret+8(FP), R1
	B tailbody<>(SB)

TEXT tailbody<>(SB),NOSPLIT,$0-0
	MOVD (R0)(R1), R2
	MOVD R2, (R1)
	RET
`
	tailFile, err := Parse(ArchARM64, tailAsm)
	if err != nil {
		t.Fatal(err)
	}
	// Reject nil resolve, nil types, namespace mismatch, missing selection, duplicate file, bad parse, filename mismatch, bodyful decl.
	if _, err := BindGoARM64ABI0TailDeclarations(GoPackage{}, tailFile, nil, nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected nil resolve error")
	}
	if _, err := BindGoARM64ABI0TailDeclarations(GoPackage{Path: "example.com/p"}, tailFile, testResolveSym("example.com/p"), nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected nil types error")
	}
	if _, err := BindGoARM64ABI0TailDeclarations(GoPackage{Path: "wrong/path", Types: tpkg}, tailFile, testResolveSym("example.com/p"), nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected namespace mismatch error")
	}
	if _, err := BindGoARM64ABI0TailDeclarations(GoPackage{Path: "example.com/p", Types: tpkg}, tailFile, testResolveSym("example.com/p"), nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected missing selection error")
	}
	dupPkg := GoPackage{
		Path: "example.com/p", Types: tpkg, Syntax: []*ast.File{af, af},
		SourceSelection: &GoSourceSelection{
			Fset: fset, TypesInfo: info, Sizes: sizes,
			SelectedGoFiles: []string{"p.go", "p.go"},
			GoSources:       map[string][]byte{"p.go": []byte(goSrc), "q.go": []byte(goSrc)},
		},
	}
	if _, err := BindGoARM64ABI0TailDeclarations(dupPkg, tailFile, testResolveSym("example.com/p"), nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected duplicate file error")
	}
	badParsePkg := GoPackage{
		Path: "example.com/p", Types: tpkg, Syntax: []*ast.File{af},
		SourceSelection: &GoSourceSelection{
			Fset: fset, TypesInfo: info, Sizes: sizes,
			SelectedGoFiles: []string{"p.go"},
			GoSources:       map[string][]byte{"p.go": []byte("package p\nfunc (((")},
		},
	}
	if _, err := BindGoARM64ABI0TailDeclarations(badParsePkg, tailFile, testResolveSym("example.com/p"), nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected parse error")
	}
	wrongNamePkg := GoPackage{
		Path: "example.com/p", Types: tpkg, Syntax: []*ast.File{af},
		SourceSelection: &GoSourceSelection{
			Fset: fset, TypesInfo: info, Sizes: sizes,
			SelectedGoFiles: []string{"other.go"},
			GoSources:       map[string][]byte{"other.go": []byte(goSrc)},
		},
	}
	if _, err := BindGoARM64ABI0TailDeclarations(wrongNamePkg, tailFile, testResolveSym("example.com/p"), nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected filename mismatch error")
	}
	emptySrcPkg := GoPackage{
		Path: "example.com/p", Types: tpkg, Syntax: []*ast.File{af},
		SourceSelection: &GoSourceSelection{
			Fset: fset, TypesInfo: info, Sizes: sizes,
			SelectedGoFiles: []string{"p.go"},
			GoSources:       map[string][]byte{"p.go": nil},
		},
	}
	if _, err := BindGoARM64ABI0TailDeclarations(emptySrcPkg, tailFile, testResolveSym("example.com/p"), nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected empty source error")
	}

	// 2. ARM64 lower_branch.go: ABI0 stack-based CALL with struct arg & single/multi results + PC-relative branches.
	arm64Pkg := mustGoPackage(t, "example.com/a64", `package a64
func Caller(s string, n uint64) (uint64, uint64)
func CalleeMulti(s string, n uint64) (uint64, uint64)
func CalleeSingle(x uint64) uint64
func CallerSingle(x uint64) uint64
func PCRel(x uint64) uint64
`)
	arm64Asm := `TEXT ·Caller(SB),NOSPLIT,$48-40
	MOVD s_base+0(FP), R0
	MOVD s_len+8(FP), R1
	MOVD n+16(FP), R2
	MOVD R0, 8(RSP)
	MOVD R1, 16(RSP)
	MOVD R2, 24(RSP)
	CALL ·CalleeMulti(SB)
	MOVD 32(RSP), R3
	MOVD 40(RSP), R4
	MOVD R3, ret+24(FP)
	MOVD R4, ret1+32(FP)
	RET

TEXT ·CallerSingle(SB),NOSPLIT,$24-16
	MOVD x+0(FP), R0
	MOVD R0, 8(RSP)
	CALL ·CalleeSingle(SB)
	MOVD 16(RSP), R1
	MOVD R1, ret+8(FP)
	RET

TEXT ·PCRel(SB),NOSPLIT,$0-16
	MOVD x+0(FP), R0
	CMP $0, R0
	BEQ 2(PC)
	B 0(PC)
done:
	MOVD R0, ret+8(FP)
	RET
`
	tr64, err := TranslateGoModule(arm64Pkg, []byte(arm64Asm), GoModuleOptions{
		SourcePreprocessed: true, GOARCH: "arm64", ResolveSym: testResolveSym("example.com/a64"),
	})
	if err != nil {
		t.Fatalf("TranslateGoModule arm64 branch/stack-ABI0: %v", err)
	}
	tr64.Module.Dispose()

	// 3. ARM internal/arm/ops.go FP float literals, conditional MOVF/MOVD, F<->R converts, SB float load/store.
	armSrc := `DATA glob<>+0(SB)/8, $0
GLOBL glob<>(SB), NOPTR, $8
TEXT ·armfp(SB),NOSPLIT,$0-0
	CMP $0, R0
	MOVF $1.5, F0
	MOVD $2.5, F1
	MOVF $3, F2
	MOVD $4, F3
	ADDF $1.25, F0
	ADDD $2.25, F1
	ADDF $2, F0
	ADDD $3, F1
	MOVFW.EQ F0, F2
	MOVFW F0, R1
	MOVWF R1, F0
	MOVWD R1, F1
	MOVF.EQ F0, F2
	MOVD.NE F1, F3
	MOVF.EQ F0, (R0)
	MOVD.NE F1, glob<>(SB)
	MOVF glob<>(SB), F0
	MOVD glob<>(SB), F1
	RET
`
	armFile, err := Parse(ArchARM, armSrc)
	if err != nil {
		t.Fatalf("Parse arm: %v", err)
	}
	armMod, err := TranslateModule(armFile, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(s string) string { return "example." + strings.TrimPrefix(s, "·") },
		Sigs:         map[string]FuncSig{"example.armfp": {Name: "example.armfp", Ret: Void}},
	})
	if err != nil {
		t.Fatalf("TranslateModule arm FP: %v", err)
	}
	armMod.Dispose()
}
