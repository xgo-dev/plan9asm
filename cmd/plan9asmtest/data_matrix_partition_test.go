package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Scheduling policy only: actual Go and LLVM objects execute in the three
// independent target owners. Their union must not become a filtered sample.
func TestReadonlyDataTargetsHaveIndependentCompleteRootOwners(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "amd64_fixed_local_data_matrix_go127_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string][2]string{
		"TestGoAMD64FixedLocalReadonlyDataLinuxRegisteredConsumers":   {"linux/amd64", "x86_64-unknown-linux-gnu"},
		"TestGoAMD64FixedLocalReadonlyDataDarwinRegisteredConsumers":  {"darwin/amd64", "x86_64-apple-darwin"},
		"TestGoAMD64FixedLocalReadonlyDataWindowsRegisteredConsumers": {"windows/amd64", "x86_64-pc-windows-msvc"},
	}
	var roots []string
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(function.Name.Name, "TestGoAMD64FixedLocalReadonlyData") ||
			!strings.HasSuffix(function.Name.Name, "RegisteredConsumers") {
			continue
		}
		target, exists := wanted[function.Name.Name]
		if !exists || function.Body == nil || len(function.Body.List) != 1 {
			t.Fatal("unknown or independently filtered literal-data owner", function.Name.Name)
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Fatal("literal-data owner is not a complete helper dispatch")
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			t.Fatal("literal-data owner changed complete target dispatch")
		}
		helper, ok := call.Fun.(*ast.Ident)
		if !ok || helper.Name != "fixedLocalDataTargetConsumers" {
			t.Fatal("literal-data owner bypassed the complete shared matrix")
		}
		for index, value := range target {
			literal, ok := call.Args[index+1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("target must remain an explicit independent role")
			}
			actual, err := strconv.Unquote(literal.Value)
			if err != nil || actual != value {
				t.Fatal("literal-data target/triple changed", actual, err)
			}
		}
		roots = append(roots, function.Name.Name)
	}
	if len(roots) != len(wanted) {
		t.Fatal("literal-data matrix lost a complete target owner", roots)
	}
	shards, err := partition(roots, 32)
	if err != nil {
		t.Fatal(err)
	}
	owners := map[int]bool{}
	for index, names := range shards {
		if len(names) == 0 {
			continue
		}
		if len(names) != 1 || owners[index%16] {
			t.Fatal("expensive complete targets share a Windows scheduling owner", names)
		}
		owners[index%16] = true
	}
}
