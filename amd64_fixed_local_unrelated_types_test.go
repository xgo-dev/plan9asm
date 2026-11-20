package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"
)

func TestGoAMD64FixedLocalUnrelatedGoTypesObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const declarations = `
type XOF interface { Read([]byte) (int, error); Clone() XOF }
type Callback func([]byte) error
type Cache map[string][]byte
type Queue chan []byte
type Scalar float64
type Node struct { Next *Node; Value uint64 }
type Box[T any] struct { Value T }
type Reader = interface { Read([]byte) (int, error) }
`
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
			name := filepath.Join(request.Directory, "value.go")
			original, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			data := append(original, []byte(declarations)...)
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			set := token.NewFileSet()
			syntax, err := parser.ParseFile(set, name, data, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			pkg.Syntax = []*ast.File{syntax}
			pkg.Types, err = (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check(pkg.Path, set, pkg.Syntax, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Target = target.name
			options.TargetTriple = target.triple
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "types.ll", "types.o", ir)
				compileLLVMToObject(t, llc, target.triple, "types-opt.ll", "types-opt.o", x86MulDivRoundOptimize(t, ir))
			})
			if len(bound.Sigs) != 1 || len(source.declarations) != 1 || len(source.functions) != 1 {
				t.Fatal("unrelated ordinary types acquired assembly transport or frame authority")
			}
		})
	}
}
