package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCMOVFixedLocalObjectsHaveIndependentTargetOwners(t *testing.T) {
	fixedLocalRequireTargetOwners(t, "amd64_cmov_fixed_local_test.go",
		"TestX86CMOVFamilyFixedLocalAUTOActualObjects", "x86CMOVFixedLocalActualObjects", 6,
		[]struct{ name, target, triple string }{
			{"Linux", "linux/amd64", "x86_64-unknown-linux-gnu"},
			{"Darwin", "darwin/amd64", "x86_64-apple-darwin"},
		})
}

func TestCMOVFixedLocalRuntimeHasIndependentBatchOwners(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", "amd64_cmov_fixed_local_runtime_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "TestCrossLinuxRuntimeMatrixX86CMOVFixedLocalAUTOWholeBytes"
	want := make(map[string]int)
	for batch := 0; batch < 7; batch++ {
		want[fmt.Sprintf("%sBatch%02d", prefix, batch)] = batch
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(function.Name.Name, prefix) {
			continue
		}
		batch, found := want[function.Name.Name]
		if !found || function.Body == nil || len(function.Body.List) != 1 {
			t.Fatal("unknown, monolithic or incomplete CMOV runtime owner", function.Name.Name)
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Fatal("runtime owner must call the complete shared plan", function.Name.Name)
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			t.Fatal("runtime owner changed its complete-plan arguments", function.Name.Name)
		}
		helper, ok := call.Fun.(*ast.Ident)
		if !ok || helper.Name != "x86CMOVFixedLocalRuntimeBatch" {
			t.Fatal("runtime owner substituted its complete-plan helper", function.Name.Name)
		}
		receiver, ok := call.Args[0].(*ast.Ident)
		if !ok || receiver.Name != "t" {
			t.Fatal("runtime batch must retain its actual test lifetime", function.Name.Name)
		}
		literal, ok := call.Args[1].(*ast.BasicLit)
		if !ok || literal.Kind != token.INT {
			t.Fatal("runtime batch index must remain literal", function.Name.Name)
		}
		actual, err := strconv.Atoi(literal.Value)
		if err != nil || actual != batch {
			t.Fatal("runtime owner changed its exact range", function.Name.Name, actual, batch)
		}
		delete(want, function.Name.Name)
	}
	if len(want) != 0 {
		t.Fatal("missing complete CMOV runtime owners", want)
	}
}

func TestCMOVFixedLocalRuntimePreparesOwnedToolCacheBeforeCapture(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", "amd64_cmov_fixed_local_runtime_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var prepared, captured []token.Pos
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "x86CMOVFixedLocalRuntimeBatch" {
			continue
		}
		for _, statement := range function.Body.List {
			ast.Inspect(statement, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				helper, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				switch helper.Name {
				case "goAMD64FramePrepareOwnedToolCache":
					direct, directOK := statement.(*ast.ExprStmt)
					if !directOK || direct.X != call || len(call.Args) != 1 {
						t.Fatal("CMOV tool cache must be prepared by the common runtime owner")
					}
					argument, valid := call.Args[0].(*ast.Ident)
					if !valid || argument.Name != "t" {
						t.Fatal("CMOV tool cache lost its actual test lifetime")
					}
					prepared = append(prepared, call.Pos())
				case "x86CMOVFixedLocalFixture":
					captured = append(captured, call.Pos())
				}
				return true
			})
		}
	}
	if len(prepared) != 1 || len(captured) != 1 || prepared[0] >= captured[0] {
		t.Fatal("CMOV runtime must prepare its process-owned lazy tool cache before independent source capture", prepared, captured)
	}
}
