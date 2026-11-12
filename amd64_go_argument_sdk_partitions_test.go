package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Check scheduling ownership without loading LLVM or capturing an SDK source.
// Actual source, translation, object and lifetime checks remain in each owner.
func TestAMD64SDKCompareAPIIndependentOwners(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_go_argument_sdk_go127_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	for _, owner := range []struct{ name, api string }{
		{"TestGoX86SDKAMD64CompareTypedArgumentsWholeSource", "text"},
		{"TestGoX86SDKAMD64CompareTypedArgumentsWholeSourceModule", "module"},
		{"TestGoX86SDKAMD64CompareTypedArgumentsWholeSourceGoModule", "go-module"},
	} {
		t.Run(owner.api, func(t *testing.T) {
			function := functions[owner.name]
			if function == nil {
				t.Fatal("missing independent complete-source API owner", owner.name)
			}
			calls := 0
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee, ok := call.Fun.(*ast.Ident)
				if !ok || callee.Name != "amd64SDKTypedArgumentsWholeSource" {
					return true
				}
				calls++
				if len(call.Args) != 3 {
					t.Error("owner must select exactly one complete-source API")
					return false
				}
				for index, want := range map[int]string{1: "compare_amd64.s", 2: owner.api} {
					literal, ok := call.Args[index].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						t.Error("member/API selection must be a literal")
						continue
					}
					got, err := strconv.Unquote(literal.Value)
					if err != nil || got != want {
						t.Errorf("selection = %q, want %q", got, want)
					}
				}
				return false
			})
			if calls != 1 {
				t.Errorf("complete-source helper calls = %d, want one", calls)
			}
		})
	}
}
