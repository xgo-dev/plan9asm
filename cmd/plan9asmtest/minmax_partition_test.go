package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeMinMaxFamiliesOccupyIndependentRootShards(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "arm64_scalar_minmax_state_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var roots []string
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && strings.HasPrefix(function.Name.Name, "TestARM64ScalarMinMaxNative") {
			roots = append(roots, function.Name.Name)
		}
	}
	if len(roots) != 4 {
		t.Fatal("native runtime lost its four exhaustive family owners", roots)
	}
	shards, err := partition(roots, 32)
	if err != nil {
		t.Fatal(err)
	}
	for index, roots := range shards {
		if len(roots) > 1 {
			t.Fatalf("expensive native families share shard %d: %v", index+1, roots)
		}
	}
}
