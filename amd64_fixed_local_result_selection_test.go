package plan9asm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGoAMD64FixedLocalResultCompleteMembersAndSelectionBoundary(t *testing.T) {
	pkg, request, _, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	first, _, _ := x86PrivateAlignedFrameAuditFixture(t, "PADDQ 16(SP),X0")
	second, _, _ := x86PrivateAlignedFrameAuditFixture(t, "AESENC 16(SP),X0")
	second = strings.Replace(second, "·Value", "·Other", 1)
	second = strings.Replace(second, "#include \"textflag.h\"\n", "", 1)
	assembly := first + "\n" + second
	declarations := "package framefixture\nfunc Value(a, b, c, d uint64) uint64\nfunc Other(a, b, c, d uint64) uint64\n"
	for name, data := range map[string]string{"value.go": declarations, request.AssemblyFile: assembly} {
		if err := os.WriteFile(filepath.Join(request.Directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "value.go", declarations, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check(pkg.Path, fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Types, pkg.Syntax = typed, []*ast.File{syntax}
	for _, name := range []string{"Value", "Other"} {
		sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name, typed.Scope().Lookup(name).(*types.Func), "amd64", sizes)
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[sig.Name] = sig
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("complete two-member actual original object/declaration precondition", err)
	}
	for _, api := range []string{"text", "context", "go-module"} {
		t.Run(api, func(t *testing.T) {
			var ir string
			if api == "text" {
				ir, err = Translate(file, bound)
			} else {
				context := llvm.NewContext()
				defer context.Dispose()
				var module llvm.Module
				if api == "context" {
					module, err = TranslateModuleInContext(context, file, bound)
				} else {
					result, translateErr := translateGoModuleInContext(context, pkg, []byte(assembly), GoModuleOptions{
						GOOS: "linux", GOARCH: "amd64", TargetTriple: bound.TargetTriple, ResolveSym: bound.ResolveSym,
						ManualSig: func(name string) (FuncSig, bool) { sig, found := bound.Sigs[name]; return sig, found },
					})
					err = translateErr
					if result != nil {
						module = result.Module
					}
				}
				if !module.IsNil() {
					defer module.Dispose()
					ir = module.String()
				}
			}
			if err != nil || !strings.Contains(ir, pkg.Path+".Value") || !strings.Contains(ir, pkg.Path+".Other") {
				t.Fatal("complete original member/renderer projection failed", err)
			}
		})
	}
	context := llvm.NewContext()
	defer context.Dispose()
	queries := 0
	result, err := translateGoModuleInContext(context, pkg, []byte(assembly), GoModuleOptions{
		GOOS: "linux", GOARCH: "amd64", TargetTriple: bound.TargetTriple, ResolveSym: bound.ResolveSym,
		ManualSig: func(name string) (FuncSig, bool) { sig, found := bound.Sigs[name]; return sig, found },
		KeepFunc:  func(_, name string) bool { queries++; return name == pkg.Path+".Other" },
	})
	if result != nil {
		if !result.Module.IsNil() {
			result.Module.Dispose()
		}
		t.Fatal("partial selection retained a whole-file native capability")
	}
	if !errors.Is(err, ErrProbeNeedsContext) || queries != 2 {
		t.Fatal("unsupported partial native selection was admitted or KeepFunc was repeated", queries, err)
	}
}
