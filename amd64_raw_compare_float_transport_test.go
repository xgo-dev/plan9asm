package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestX86RawLegacyFloatingCompareRuntimeRequiresOwnedGuestTransport(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_raw_compare_float_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	const required = "TestCrossLinuxRuntimeMatrixX86RawLegacyFloatingCompareRuntime"
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == required {
			body = function.Body
		}
	}
	if body == nil {
		t.Fatal("raw compare runtime is not registered in the required cross-runtime matrix")
	}

	tools, consumer := 0, 0
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if function, ok := call.Fun.(*ast.Ident); ok && function.Name == "x86FloatCompareExecutionTools" {
			tools++
		}
		if method, ok := call.Fun.(*ast.SelectorExpr); ok {
			if method.Sel.Name == "Skip" || method.Sel.Name == "Skipf" || method.Sel.Name == "SkipNow" {
				t.Fatal("required raw compare execution cannot substitute a host skip for its guest counterpart")
			}
			if receiver, ok := method.X.(*ast.Ident); ok && receiver.Name == "execution" && method.Sel.Name == "compileAndRunLLVM" {
				consumer++
			}
		}
		return true
	})
	if tools != 1 || consumer != 1 {
		t.Fatalf("required raw comparison must consume its authenticated tools and execution route exactly once: tools=%d consumer=%d", tools, consumer)
	}
}
