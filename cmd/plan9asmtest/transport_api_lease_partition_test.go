package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

var transportCompleteLeaseOwners = []struct{ filename, function string }{
	{"amd64_fixed_local_transport_runtime_test.go", "TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalTransportByteValues"},
	{"amd64_fixed_local_transport_test.go", "TestGoAMD64FixedLocalTransportActualObjects"},
	{"amd64_fixed_local_nontemporal_test.go", "fixedLocalNonTemporalActualObjects"},
}

// A complete three-API matrix cannot borrow one owner started before the first
// API. The real capture/close and source-revocation tests remain independent.
func TestFixedLocalTransportCompleteConsumersHaveFreshAPILeases(t *testing.T) {
	for _, owner := range transportCompleteLeaseOwners {
		t.Run(owner.function, func(t *testing.T) {
			function := transportLeaseFunction(t, owner.filename, owner.function)
			fresh := 0
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := transportLeaseCallName(call)
				switch name {
				case "requireGoAMD64FrameCapture", "CaptureGoAMD64FrameSource", "runtimeOracleStageContext", "runtimeOracleProofContext", "fixedLocalAPIs":
					t.Errorf("complete consumer still shares an outer %s", name)
				case "source.BindFixedLocal", "owner.BindFixedLocal", "observer.BindFixedLocal":
					t.Error("bound options must belong only to the current fresh API")
				case "fixedLocalFreshAPIs":
					fresh++
					if len(call.Args) != 6 {
						t.Fatal("complete consumer lost its exact source/request/check arguments")
					}
					for index, want := range []string{"t", "pkg", "request", "options"} {
						got, ok := call.Args[index].(*ast.Ident)
						if !ok || got.Name != want {
							t.Fatal("fresh owner substituted its original complete source", index)
						}
					}
					apis, ok := call.Args[4].(*ast.CompositeLit)
					if !ok || len(apis.Elts) != 3 {
						t.Fatal("complete source must retain all three public APIs")
					}
					for index, want := range []string{"Translate", "Module", "GoModule"} {
						literal, ok := apis.Elts[index].(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							t.Fatal("public API inventory must be explicit")
						}
						got, err := strconv.Unquote(literal.Value)
						if err != nil || got != want {
							t.Fatal("cropped, repeated or substituted public API", got, err)
						}
					}
				}
				return true
			})
			if fresh != 1 {
				t.Fatal("complete source needs exactly one fresh three-API plan", fresh)
			}
		})
	}
}

func TestFixedLocalTransportCompleteConsumersOwnPreparedCompilerArtifacts(t *testing.T) {
	for _, owner := range transportCompleteLeaseOwners {
		t.Run(owner.function, func(t *testing.T) {
			fixedLocalRequireOwnedObjectCache(t, owner.filename, owner.function)
			fixedLocalRequirePreparedTools(t, owner.filename, owner.function)
		})
	}
}

func transportLeaseFunction(t *testing.T, filename, name string) *ast.FuncDecl {
	t.Helper()
	syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", filename), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name {
			return function
		}
	}
	t.Fatal("missing complete transport/streaming consumer", name)
	return nil
}

func transportLeaseCallName(call *ast.CallExpr) string {
	if name, ok := call.Fun.(*ast.Ident); ok {
		return name.Name
	}
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		if receiver, ok := selector.X.(*ast.Ident); ok {
			return receiver.Name + "." + selector.Sel.Name
		}
	}
	return ""
}
