package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestARM64RNDRRequiredOriginalRuntimeOwner(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(), "arm64_rndr_cross_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestCrossLinuxRuntimeMatrixARM64RNDR" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "arm64RNDRFullStateRuntime" {
					calls++
				}
			}
			return true
		})
	}
	if calls != 1 {
		t.Fatal("required Linux RNG owner lost its full original-Go oracle", calls)
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") ||
		!strings.Contains(string(workflow), "PLAN9ASM_CROSS_EXEC: '1'") {
		t.Fatal("CI lost mandatory RNG runtime selection", err)
	}
}
