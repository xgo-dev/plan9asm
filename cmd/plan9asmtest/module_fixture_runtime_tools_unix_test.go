//go:build unix

package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func moduleFixtureRelocatedLLVMTools(cross bool) []string {
	names := []string{"llc", "clang", "llvm-as", "opt", "llvm-dis", "llvm-objdump", "llvm-nm"}
	if cross {
		names = append(names, "ld.lld")
	}
	return names
}

// This is a fixture maintenance tripwire, not a new tool-selection authority.
// Actual captureCIScope still selects and checks every runtime tool itself.
func moduleFixtureActualRuntimeToolRoles(t *testing.T) (base, cross []string) {
	t.Helper()
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "ci_scope.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var capture *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "captureCIScope" {
			if capture != nil {
				t.Fatal("duplicate scope producer")
			}
			capture = function
		}
	}
	if capture == nil {
		t.Fatal("actual runtime scope producer is absent")
	}
	stringsFrom := func(expressions []ast.Expr) []string {
		var result []string
		for _, expression := range expressions {
			literal, ok := expression.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("runtime role table changed from explicit string roles")
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, value)
		}
		return result
	}
	var predicates int
	ast.Inspect(capture.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
			name, _ := assignment.Lhs[0].(*ast.Ident)
			if name != nil && name.Name == "names" && assignment.Tok == token.DEFINE {
				literal, ok := assignment.Rhs[0].(*ast.CompositeLit)
				if !ok || base != nil {
					t.Fatal("actual base runtime role table changed")
				}
				base = stringsFrom(literal.Elts)
			}
			if name != nil && name.Name == "llvmTool" {
				var predicate bytes.Buffer
				if err := printer.Fprint(&predicate, set, assignment.Rhs[0]); err != nil {
					t.Fatal(err)
				}
				if predicate.String() != `name == "clang" || name == "llc" || name == "opt" || name == "ld.lld" || strings.HasPrefix(name, "llvm-")` {
					t.Fatal("actual LLVM bindir predicate changed; update fixture role observation", predicate.String())
				}
				predicates++
			}
		}
		conditional, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		condition, _ := conditional.Cond.(*ast.Ident)
		if condition == nil || condition.Name != "cross" {
			return true
		}
		for _, statement := range conditional.Body.List {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			name, _ := assignment.Lhs[0].(*ast.Ident)
			if name == nil || name.Name != "names" {
				continue
			}
			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if !ok || len(call.Args) < 2 || cross != nil {
				t.Fatal("actual cross runtime role table changed")
			}
			function, _ := call.Fun.(*ast.Ident)
			first, _ := call.Args[0].(*ast.Ident)
			if function == nil || function.Name != "append" || first == nil || first.Name != "names" {
				t.Fatal("actual cross runtime role append changed")
			}
			cross = stringsFrom(call.Args[1:])
		}
		return true
	})
	if len(base) == 0 || len(cross) == 0 || predicates != 1 {
		t.Fatal("incomplete actual runtime role observation")
	}
	return base, cross
}

func TestModuleFixtureRelocatedLLVMToolsCoverActualRuntimeRoles(t *testing.T) {
	base, additional := moduleFixtureActualRuntimeToolRoles(t)
	for _, cross := range []bool{false, true} {
		t.Run(strconv.FormatBool(cross), func(t *testing.T) {
			actual := append([]string(nil), base...)
			if cross {
				actual = append(actual, additional...)
			}
			var required []string
			for _, name := range actual {
				if name != "llvm-config" && (name == "clang" || name == "llc" || name == "opt" || name == "ld.lld" || strings.HasPrefix(name, "llvm-")) {
					required = append(required, name)
				}
			}
			if got := moduleFixtureRelocatedLLVMTools(cross); !reflect.DeepEqual(got, required) {
				t.Fatalf("relocated fixture omitted or added actual LLVM runtime roles: got=%v required=%v", got, required)
			}
		})
	}
}
