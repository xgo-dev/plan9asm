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

func TestPreprocessAssemblyAndObserveCPP(t *testing.T) {
	src := `#define VAL 42
#ifdef GOAMD64_v2
TEXT ·f(SB),NOSPLIT,$0-8
	MOVQ $VAL, AX
	MOVQ AX, ret+0(FP)
	RET
#endif
`
	defines, err := GoAssemblerDefinesForEnvironment("linux", "amd64", map[string]string{
		"GOOS":      "linux",
		"GOARCH":    "amd64",
		"GOAMD64":   "v2",
		"GOVERSION": "go1.27.3",
	})
	if err != nil {
		t.Fatalf("GoAssemblerDefinesForEnvironment: %v", err)
	}
	obs, tokens, err := ObserveAssemblyCPPOutput(src, AssemblyPreprocessOptions{
		FileName: "f_amd64.s",
		Defines:  defines,
	})
	if err != nil {
		t.Fatalf("ObserveAssemblyCPPOutput: %v", err)
	}
	if len(tokens) == 0 || len(obs.Events) == 0 {
		t.Fatalf("unexpected preprocessed tokens=%d events=%d", len(tokens), len(obs.Events))
	}
	out, err := PreprocessAssemblySource(src, AssemblyPreprocessOptions{FileName: "f_amd64.s", Defines: defines})
	if err != nil || !strings.Contains(out, "$42") {
		t.Fatalf("PreprocessAssemblySource: err=%v out=%q", err, out)
	}
	obs2, err := ObserveAssemblyCPP(src, AssemblyPreprocessOptions{FileName: "f_amd64.s", Defines: defines})
	if err != nil || len(obs2.Events) == 0 {
		t.Fatalf("ObserveAssemblyCPP: err=%v events=%d", err, len(obs2.Events))
	}
	// Verify ARM conditional dot-suffix spacing is preserved.
	armOut, err := PreprocessAssemblySource("TEXT ·g(SB),NOSPLIT,$0\n\tMOVW.LT R1, R2\n\tB.EQ done\ndone:\n\tRET\n", AssemblyPreprocessOptions{FileName: "g_arm.s"})
	if err != nil {
		t.Fatalf("PreprocessAssemblySource arm: %v", err)
	}
	if !strings.Contains(armOut, "MOVW.LT ") || !strings.Contains(armOut, "B.EQ ") {
		t.Fatalf("ARM conditional suffix split unexpectedly:\n%s", armOut)
	}
}

func TestGoAssemblyHeaderAndUint128ABI0(t *testing.T) {
	src := `package p
const Answer = 7
type Pair struct { Lo, Hi uint64 }
func Wrap(p *byte, a, b Pair, res uintptr) int32
func Impl(p *byte, a, b Pair, res uintptr) int32
`
	pkg := mustGoPackage(t, "example.com/p", src)
	hdrBytes, err := GoAssemblyHeader(pkg, "amd64")
	if err != nil {
		t.Fatalf("GoAssemblyHeader: %v", err)
	}
	hdr := string(hdrBytes)
	if !strings.Contains(hdr, "#define const_Answer 7") || !strings.Contains(hdr, "#define Pair_Hi 8") {
		t.Fatalf("unexpected go_asm.h:\n%s", hdr)
	}

	asmSrc := `TEXT ·Wrap(SB),$56-52
	MOVQ p+0(FP), AX
	MOVQ AX, 0(SP)
	MOVQ a_Lo+8(FP), AX
	MOVQ AX, 8(SP)
	MOVQ a_Hi+(8+8)(FP), AX
	MOVQ AX, 16(SP)
	MOVQ b_Lo+24(FP), AX
	MOVQ AX, 24(SP)
	MOVQ b_Hi+32(FP), AX
	MOVQ AX, 32(SP)
	MOVQ res+40(FP), AX
	MOVQ AX, 40(SP)
	PREFETCHT0 (AX)
	CALL ·Impl(SB)
	MOVL 48(SP), AX
	MOVL AX, ret+48(FP)
	RET
`
	tr, err := TranslateGoModule(pkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true,
		FileName:           "wrap_amd64.s",
		GOOS:               "linux",
		GOARCH:             "amd64",
		ResolveSym:         testResolveSym("example.com/p"),
	})
	if err != nil {
		t.Fatalf("TranslateGoModule Pair ABI0: %v", err)
	}
	defer tr.Module.Dispose()
	ir := tr.Module.String()
	if !strings.Contains(ir, "extractvalue { i64, i64 } %arg1, 1") {
		t.Fatalf("missing struct field extraction:\n%s", ir)
	}

	fn := pkg.Types.Scope().Lookup("Wrap").(*types.Func)
	sig, err := DeriveGoFuncABI0Signature("example.com/p.Wrap", fn, "amd64", types.SizesFor("gc", "amd64"))
	if err != nil || len(sig.Frame.Params) != 6 || len(sig.Frame.Results) != 1 {
		t.Fatalf("DeriveGoFuncABI0Signature = (%+v, %v)", sig, err)
	}
}

func TestARM64SBAndABI0StackCallAndTailSelection(t *testing.T) {
	goSrc := "package p\nfunc Copy(dst, src *byte, n uintptr) uint64\nfunc Helper(dst, src *byte, n uintptr)\nfunc Tail(x uint64) uint64\n"
	dir := t.TempDir()
	goPath := filepath.Join(dir, "p.go")
	if err := os.WriteFile(goPath, []byte(goSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, goPath, goSrc, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	sizes := types.SizesFor("gc", "arm64")
	tpkg, err := (&types.Config{Sizes: sizes}).Check("example.com/p", fset, []*ast.File{af}, info)
	if err != nil {
		t.Fatal(err)
	}
	pkg := GoPackage{
		Path:   "example.com/p",
		Types:  tpkg,
		Syntax: []*ast.File{af},
		SourceSelection: &GoSourceSelection{
			Fset:            fset,
			TypesInfo:       info,
			Sizes:           sizes,
			SelectedGoFiles: []string{goPath},
			GoSources:       map[string][]byte{goPath: []byte(goSrc)},
		},
	}

	// Verify ARM64 SB barrier + physical RSP stack-ABI0 outgoing call + tail binding.
	asmSrc := `TEXT ·Copy(SB),NOSPLIT,$40-32
	SB
	MOVD dst+0(FP), R7
	MOVD src+8(FP), R6
	MOVD n+16(FP), R4
	MOVD R7, 8(RSP)
	MOVD R6, 16(RSP)
	MOVD R4, 24(RSP)
	CALL ·Helper(SB)
	MOVD R4, ret+24(FP)
	RET

TEXT ·Tail(SB),NOSPLIT,$0-16
	MOVD x+0(FP), R0
	MOVD $ret+8(FP), R1
	B tailbody<>(SB)

TEXT tailbody<>(SB),NOSPLIT,$0-0
	MOVD R0, (R1)
	RET
`
	tr, err := TranslateGoModule(pkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true,
		FileName:           "copy_arm64.s",
		TargetTriple:       "arm64-apple-darwin",
		GOOS:               "darwin",
		GOARCH:             "arm64",
		ResolveSym:         testResolveSym("example.com/p"),
	})
	if err != nil {
		t.Fatalf("TranslateGoModule arm64: %v", err)
	}
	defer tr.Module.Dispose()
	ir := tr.Module.String()
	if !strings.Contains(ir, `.inst 0xd50330ff`) || !strings.Contains(ir, "%local_stack") {
		t.Fatalf("missing SB or local_stack in arm64 IR:\n%s", ir)
	}

	// Tampered SourceSelection must be rejected with ErrProbeNeedsContext.
	badPkg := pkg
	badPkg.SourceSelection = &GoSourceSelection{
		Fset:            fset,
		TypesInfo:       info,
		Sizes:           sizes,
		SelectedGoFiles: []string{goPath},
		GoSources:       map[string][]byte{goPath: []byte("package p\nfunc Other()\n")},
	}
	if _, err := TranslateGoModule(badPkg, []byte(asmSrc), GoModuleOptions{
		SourcePreprocessed: true,
		FileName:           "copy_arm64.s",
		TargetTriple:       "arm64-apple-darwin",
		GOOS:               "darwin",
		GOARCH:             "arm64",
		ResolveSym:         testResolveSym("example.com/p"),
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected ErrProbeNeedsContext on tampered SourceSelection, got %v", err)
	}
}

func TestGoAMD64FrameSourceLifecycle(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not found")
	}
	dir := t.TempDir()
	goSrc := "package p\nfunc Add(x uint64) uint64\n"
	asmSrc := "TEXT ·Add(SB),NOSPLIT,$8-16\n\tMOVQ x+0(FP), AX\n\tMOVQ AX, 0(SP)\n\tMOVQ 0(SP), BX\n\tMOVQ BX, ret+8(FP)\n\tRET\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/p\ngo 1.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(goSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p_amd64.s"), []byte(asmSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "example.com/p", goSrc)
	fs, err := CaptureGoAMD64FrameSource(context.Background(), pkg, GoAMD64FrameCaptureRequest{
		GoBinary:     goBin,
		Directory:    dir,
		AssemblyFile: "p_amd64.s",
		Target:       "linux/amd64",
		Environment:  append(os.Environ(), "GOROOT="+runtime.GOROOT()),
	})
	if err != nil {
		t.Fatalf("CaptureGoAMD64FrameSource: %v", err)
	}
	defer fs.Close()
	ctx := context.Background()
	if err := fs.Verify(ctx); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	parsed, err := Parse(ArchAMD64, asmSrc)
	if err != nil {
		t.Fatal(err)
	}
	addFn := pkg.Types.Scope().Lookup("Add").(*types.Func)
	addSig, err := DeriveGoFuncABI0Signature("example.com/p.Add", addFn, "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	boundOpt, err := fs.BindFixedLocal(ctx, pkg, parsed, Options{
		Goarch:     "amd64",
		ResolveSym: testResolveSym("example.com/p"),
		Sigs:       map[string]FuncSig{"example.com/p.Add": addSig},
	})
	if err != nil || len(boundOpt.Sigs) == 0 {
		t.Fatalf("BindFixedLocal: sigs=%+v err=%v", boundOpt.Sigs, err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Lease must now reject verification after Close.
	if err := fs.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("expected ErrProbeNeedsContext after Close, got %v", err)
	}
}
