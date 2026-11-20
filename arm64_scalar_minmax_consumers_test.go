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

func TestARM64ScalarMinMaxRuntimeMatrixOwnership(t *testing.T) {
	if len(arm64MinMaxCases()) != 20 || len(arm64MinMaxStateCases(true)) != 820 || len(arm64MinMaxStateCases(false)) != 40 {
		t.Fatal("changed complete named/raw bank/state denominator")
	}
	for _, bits := range []int{16, 32, 64} {
		if len(arm64MinMaxSamples(bits, true)) != 2 || len(arm64MinMaxSamples(bits, false)) != 324 {
			t.Fatal("changed independent control/status/input denominator", bits)
		}
	}
	const filename = "arm64_scalar_minmax_runtime_linux_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"js", "wasm"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", filename)
		if err != nil || selected != (target.os == "linux") {
			t.Fatal("required min/max source-selection role changed", target, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"TestCrossLinuxRuntimeMatrixARM64ScalarMinMaxDeadNative": "arm64MinMaxDeadRuntime",
		"arm64MinMaxLinuxFamilyRuntime":                          "arm64MinMaxStateRuntimeFamily",
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		helper, required := want[function.Name.Name]
		if !required {
			continue
		}
		calls := 0
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == helper {
				calls++
				if helper == "arm64MinMaxStateRuntimeFamily" {
					last, ok := call.Args[len(call.Args)-1].(*ast.Ident)
					if !ok || last.Name != "true" {
						t.Error("required Linux owner lost actual NEP/AH effect requirement")
					}
				}
			}
			return true
		})
		if calls != 1 {
			t.Fatalf("required owner %s lost its exact native helper", function.Name.Name)
		}
		delete(want, function.Name.Name)
	}
	if len(want) != 0 {
		t.Fatal("required native roots absent", want)
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") || !strings.Contains(string(workflow), "PLAN9ASM_CROSS_EXEC: '1'") {
		t.Fatal("CI lost mandatory native min/max selection", err)
	}
}
