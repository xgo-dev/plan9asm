package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func TestLoweredNumericalReadsDispatchBeforeNativeFamilies(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", "amd64_scalar_fp_native_read.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var transfer *ast.FuncLit
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "checkLoweredScalarFPResultInitialization" {
			continue
		}
		for _, statement := range function.Body.List {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if ok && name.Name == "transfer" {
				transfer, _ = assignment.Rhs[0].(*ast.FuncLit)
			}
		}
	}
	if transfer == nil {
		t.Fatal("missing paired lowering transfer")
	}
	var first []string
	for _, statement := range transfer.Body.List {
		branch, ok := statement.(*ast.IfStmt)
		if !ok {
			continue
		}
		assignment, ok := branch.Init.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 {
			t.Fatal("source dispatch lost its explicit checked transfer")
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok {
			t.Fatal("source dispatch lost its direct consumer call")
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok {
			t.Fatal("a generic native role preceded authenticated source dispatch")
		}
		first = append(first, name.Name)
		if len(first) == 2 {
			break
		}
	}
	if len(first) != 2 || first[0] != "x86ResultSDKLiteralStep" || first[1] != "x86ResultNumericalReadStep" {
		t.Fatal("native families shadow authenticated source consumers", first)
	}
}
