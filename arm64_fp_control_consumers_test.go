package plan9asm

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestARM64FPControlRequiredRuntimeOwners(t *testing.T) {
	const filename = "arm64_fp_control_runtime_linux_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"},
		{"windows", "amd64"}, {"js", "wasm"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", filename)
		if err != nil || selected != (target.os == "linux") {
			t.Fatal("FP control native owner source selection changed", target, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, helper := range map[string]string{
		"TestCrossLinuxRuntimeMatrixARM64FPControlFlags": "arm64FPControlFlagsRuntime",
		"TestCrossLinuxRuntimeMatrixARM64FPControlState": "arm64FPControlStateRuntime",
	} {
		calls := 0
		for _, declaration := range syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != name {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok {
					if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == helper {
						calls++
					}
				}
				return true
			})
		}
		if calls != 1 {
			t.Errorf("required native owner %s lost its real oracle %s", name, helper)
		}
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") ||
		!strings.Contains(string(workflow), "PLAN9ASM_CROSS_EXEC: '1'") {
		t.Fatal("CI no longer selects and enables the FP control runtime owners", err)
	}
}
