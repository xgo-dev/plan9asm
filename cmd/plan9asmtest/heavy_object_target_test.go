package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

func TestHeavyImmediateScratchObjectTargets(t *testing.T) {
	want := map[string]string{
		"TestARM64GPImmediateScratchCompleteObjects":            "aarch64-unknown-linux-gnu",
		"TestARM64GPImmediateScratchCompleteObjectsLinuxMusl":   "aarch64-unknown-linux-musl",
		"TestARM64GPImmediateScratchCompleteObjectsDarwin":      "aarch64-apple-darwin",
		"TestARM64GPImmediateScratchCompleteObjectsWindowsMSVC": "aarch64-pc-windows-msvc",
		"TestARM64GPImmediateScratchCompleteObjectsWindowsGNU":  "aarch64-w64-windows-gnu",
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "arm64_gp_immediate_runtime_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[string]bool)
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		triple, selected := want[function.Name.Name]
		if !selected {
			continue
		}
		found[function.Name.Name] = true
		if function.Body == nil || len(function.Body.List) != 1 {
			t.Errorf("%s must own one complete target invocation", function.Name.Name)
			continue
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Errorf("%s has no complete target invocation", function.Name.Name)
			continue
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			t.Errorf("%s lost its complete target arguments", function.Name.Name)
			continue
		}
		helper, ok := call.Fun.(*ast.Ident)
		if !ok || helper.Name != "testARM64GPImmediateScratchCompleteObjects" {
			t.Errorf("%s bypasses the complete object helper", function.Name.Name)
			continue
		}
		literal, ok := call.Args[1].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Errorf("%s has no independent literal target", function.Name.Name)
			continue
		}
		actual, err := strconv.Unquote(literal.Value)
		if err != nil || actual != triple {
			t.Errorf("%s target = %q, want %q", function.Name.Name, actual, triple)
		}
	}
	for name := range want {
		if !found[name] {
			t.Error("missing complete object target owner", name)
		}
	}

	for _, count := range []int{32, 64} {
		owners := completeObjectFamilyOwners(count)
		seen := make(map[int]string)
		for name := range want {
			owner, ok := owners[name]
			if !ok {
				t.Error("missing scheduled complete target", name)
				continue
			}
			if previous, duplicate := seen[owner]; duplicate {
				t.Error("complete target owners collide", count, previous, name, owner)
			}
			seen[owner] = name
		}
	}
}
