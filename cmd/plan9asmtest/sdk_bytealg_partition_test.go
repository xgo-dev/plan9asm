package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func checkSDKBytealgRootOwners(source []byte) error {
	syntax, err := parser.ParseFile(token.NewFileSet(), "bytealg_test.go", source, 0)
	if err != nil {
		return err
	}
	wanted := map[string]string{
		"TestCompileOneX86SDKBytealgCountExistingObjects":     "count_amd64.s",
		"TestCompileOneX86SDKBytealgIndexByteExistingObjects": "indexbyte_amd64.s",
	}
	var roots []string
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(function.Name.Name, "TestCompileOneX86SDKBytealg") {
			continue
		}
		filename, exists := wanted[function.Name.Name]
		if !exists || function.Body == nil || len(function.Body.List) != 1 {
			return fmt.Errorf("SDK bytealg needs independent complete file owners: %s", function.Name.Name)
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return fmt.Errorf("SDK bytealg owner is not a whole-file dispatch")
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return fmt.Errorf("SDK bytealg owner changed its complete dispatch")
		}
		helper, ok := call.Fun.(*ast.Ident)
		if !ok || helper.Name != "compileX86SDKBytealgExistingObject" {
			return fmt.Errorf("SDK bytealg owner bypasses the whole-file helper")
		}
		literal, ok := call.Args[1].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return fmt.Errorf("SDK bytealg owner lost its exact original member")
		}
		actual, err := strconv.Unquote(literal.Value)
		if err != nil || actual != filename {
			return fmt.Errorf("SDK bytealg owner changed its original member: %s", actual)
		}
		roots = append(roots, function.Name.Name)
	}
	if len(roots) != len(wanted) {
		return fmt.Errorf("SDK bytealg lost a complete file owner: %v", roots)
	}
	shards, err := partition(roots, 8)
	if err != nil {
		return err
	}
	owners := make(map[int]bool)
	for index, names := range shards {
		if len(names) == 0 {
			continue
		}
		if len(names) != 1 || owners[index%4] {
			return fmt.Errorf("SDK bytealg files share a Windows scheduling owner: %v", names)
		}
		owners[index%4] = true
	}
	return nil
}

func TestSDKBytealgFilesHaveIndependentCompleteRootOwners(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "plan9asmll", "x86_sdk_numerical_source_go127_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSDKBytealgRootOwners(source); err != nil {
		t.Fatal(err)
	}
}

func TestSDKBytealgRootOwnershipRejectsReducedOrSharedMatrix(t *testing.T) {
	const source = `package main
func TestCompileOneX86SDKBytealgCountExistingObjects(t *testing.T) {
	compileX86SDKBytealgExistingObject(t, "count_amd64.s")
}
func TestCompileOneX86SDKBytealgIndexByteExistingObjects(t *testing.T) {
	compileX86SDKBytealgExistingObject(t, "indexbyte_amd64.s")
}
`
	if err := checkSDKBytealgRootOwners([]byte(source)); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]string{
		"missing-file": strings.Replace(source, "TestCompileOneX86SDKBytealgIndexByteExistingObjects", "disabledIndexByte", 1),
		"same-file":    strings.Replace(source, "indexbyte_amd64.s", "count_amd64.s", 1),
		"subset":       strings.Replace(source, "compileX86SDKBytealgExistingObject", "compileOnlySelectedFunctions", 1),
		"shared-root":  strings.Replace(source, "TestCompileOneX86SDKBytealgCountExistingObjects", "TestCompileOneX86SDKBytealgExistingObjects", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkSDKBytealgRootOwners([]byte(changed)); err == nil {
				t.Fatal("reduced/shared SDK bytealg matrix passed scheduling verification")
			}
		})
	}
}
