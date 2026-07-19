package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

func TestTranslateGoModule_UsesDeclsAndLinkname(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func Compare(a, b int) int
//go:linkname cmp runtime.cmp
func cmp(a, b int) int
`)

	asm := []byte(`TEXT ·Compare(SB),NOSPLIT,$0-24
	CALL runtime·cmp(SB)
	MOVD $0, R0
	RET
`)

	tr, err := TranslateGoModule(pkg, asm, GoModuleOptions{
		FileName:     "compare_arm64.s",
		GOARCH:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym:   testResolveSym("test/pkg"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()

	if _, ok := tr.Signatures["test/pkg.Compare"]; !ok {
		t.Fatalf("missing package function signature")
	}
	if _, ok := tr.Signatures["runtime.cmp"]; !ok {
		t.Fatalf("missing go:linkname target signature")
	}
	if got := tr.Functions[0].ResolvedSymbol; got != "test/pkg.Compare" {
		t.Fatalf("resolved symbol: got %q", got)
	}
}

func TestTranslateGoModule_UsesManualSigForPlainLocalHelper(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func IndexByte(b []byte, c byte) int
`)
	manualCalled := false
	asm := []byte(`TEXT ·IndexByte(SB),NOSPLIT,$0-40
	B indexbytebody<>(SB)

TEXT indexbytebody<>(SB),NOSPLIT,$0
	MOVD $0, R0
	RET
`)

	tr, err := TranslateGoModule(pkg, asm, GoModuleOptions{
		FileName:     "indexbyte_arm64.s",
		GOARCH:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym:   testResolveSym("test/pkg"),
		ManualSig: func(resolved string) (FuncSig, bool) {
			if resolved != "test/pkg.indexbytebody" {
				return FuncSig{}, false
			}
			manualCalled = true
			return FuncSig{Name: resolved, Args: []LLVMType{"{ ptr, i64, i64 }", "i8"}, Ret: I64}, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	if !manualCalled {
		t.Fatalf("manual signature callback was not used")
	}
	if _, ok := tr.Signatures["test/pkg.indexbytebody"]; !ok {
		t.Fatalf("missing manual helper signature")
	}
}

func TestTranslateGoModule_UsesManualSigExternalName(t *testing.T) {
	pkg := mustGoPackage(t, "test/pkg", `package testpkg
func Call()
`)
	asm := []byte(`TEXT ·Call(SB),NOSPLIT,$0-0
	CALL runtime·memmove(SB)
	RET
`)

	for _, goarch := range []string{"amd64", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			tr, err := TranslateGoModule(pkg, asm, GoModuleOptions{
				FileName:   "call_" + goarch + ".s",
				GOARCH:     goarch,
				ResolveSym: testResolveSym("test/pkg"),
				ManualSig: func(resolved string) (FuncSig, bool) {
					if resolved != "runtime.memmove" {
						return FuncSig{}, false
					}
					return FuncSig{Name: "memmove", Args: []LLVMType{Ptr, Ptr, I64}, Ret: Ptr}, true
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Module.Dispose()
			ir := tr.Module.String()
			if !strings.Contains(ir, "@memmove") || strings.Contains(ir, "runtime.memmove") {
				t.Fatalf("manual external name not applied:\n%s", ir)
			}
		})
	}
}

func mustGoPackage(t *testing.T, pkgPath, src string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "pkg.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{}
	pkg, err := conf.Check(pkgPath, fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: pkgPath, Types: pkg, Syntax: []*ast.File{f}}
}

func testResolveSym(pkgPath string) func(string) string {
	return func(sym string) string {
		sym = goStripABISuffix(sym)
		if strings.HasPrefix(sym, "·") {
			return pkgPath + "." + strings.TrimPrefix(sym, "·")
		}
		if !strings.Contains(sym, "·") && !strings.Contains(sym, ".") && !strings.Contains(sym, "/") {
			return pkgPath + "." + sym
		}
		sym = strings.ReplaceAll(sym, "∕", "/")
		return strings.ReplaceAll(sym, "·", ".")
	}
}
