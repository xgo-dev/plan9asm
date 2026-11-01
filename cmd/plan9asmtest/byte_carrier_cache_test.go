package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkByteCarrierParentBuildCache(source []byte, name string) error {
	file, err := parser.ParseFile(token.NewFileSet(), "carrier_test.go", source, 0)
	if err != nil {
		return err
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name || function.Body == nil {
			continue
		}
		caches := make(map[string]bool)
		for _, statement := range function.Body.List {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			variable, variableOK := assignment.Lhs[0].(*ast.Ident)
			call, callOK := assignment.Rhs[0].(*ast.CallExpr)
			if !variableOK || !callOK || len(call.Args) != 0 {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if receiver, valid := selectorReceiver(selector); ok && valid && receiver == "t" && selector.Sel.Name == "TempDir" {
				caches[variable.Name] = true
			}
		}
		requests := 0
		var requestError error
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			helper, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch helper.Name {
			case "arm64ByteCarrierRequest":
				requestError = fmt.Errorf("%s recreates a cold builtin-tool cache inside its matrix", name)
			case "arm64ByteCarrierRequestWithBuildCache":
				requests++
				if len(call.Args) != 4 {
					requestError = fmt.Errorf("%s changed its independent source request", name)
					break
				}
				cache, ok := call.Args[3].(*ast.Ident)
				if !ok || !caches[cache.Name] {
					requestError = fmt.Errorf("%s needs a parent-owned build cache", name)
				}
			}
			return true
		})
		if requestError != nil {
			return requestError
		}
		if requests != 1 {
			return fmt.Errorf("%s lost its shared-cache request: %d", name, requests)
		}
		return nil
	}
	return fmt.Errorf("missing complete carrier matrix %s", name)
}

func selectorReceiver(selector *ast.SelectorExpr) (string, bool) {
	if selector == nil {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return receiver.Name, true
}

func TestByteCarrierMatricesReuseOnlyParentBuildCache(t *testing.T) {
	for name, filename := range map[string]string{
		"TestARM64ByteCarrierTwoScalarNativeWidthConsumers":        "arm64_byte_carrier_two_scalar_go127_test.go",
		"TestARM64ByteCarrierSignedCompleteWidthObjects":           "arm64_byte_carrier_signed_matrix_go127_test.go",
		"TestARM64ByteCarrierConsumersRejectUnclosedNativeEffects": "arm64_byte_carrier_effects_go127_test.go",
	} {
		t.Run(name, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("..", "..", filename))
			if err != nil {
				t.Fatal(err)
			}
			if err := checkByteCarrierParentBuildCache(source, name); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestByteCarrierCachePolicyRejectsColdAndChildOwnedCaches(t *testing.T) {
	const source = `package main
func TestMatrix(t *testing.T) {
	buildCache := t.TempDir()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			request := arm64ByteCarrierRequestWithBuildCache(t, directory, packagePath, buildCache)
			consume(request)
		})
	}
}
`
	if err := checkByteCarrierParentBuildCache([]byte(source), "TestMatrix"); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]string{
		"cold":        strings.Replace(source, "arm64ByteCarrierRequestWithBuildCache(t, directory, packagePath, buildCache)", "arm64ByteCarrierRequest(t, directory, packagePath)", 1),
		"child-owned": strings.Replace(source, "buildCache := t.TempDir()", "", 1),
		"per-request": strings.Replace(source, "packagePath, buildCache)", "packagePath, t.TempDir())", 1),
		"wrong-cache": strings.Replace(source, "packagePath, buildCache)", "packagePath, anotherCache)", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkByteCarrierParentBuildCache([]byte(changed), "TestMatrix"); err == nil {
				t.Fatal("unshared or unowned build cache passed matrix policy")
			}
		})
	}
}
