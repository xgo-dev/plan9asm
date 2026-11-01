package gostaticstorage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func TestGoStaticStorageCaptureAndLiveSelectionArguments(t *testing.T) {
	// These unready objects test only pure command construction. They carry no
	// observed source, original compiler archive or storage authority.
	for _, row := range []struct {
		protocol, path string
		capture, live  []string
	}{
		{Protocol, "example.invalid/owner",
			[]string{"list", "-deps", "-json", "-compiled", "-export", "-a", "-p=1", "-mod=readonly", "."},
			[]string{"list", "-deps", "-json", "-compiled", "-export", "-p=1", "-mod=readonly", "."}},
		{SDKCPUProtocol, "internal/cpu",
			[]string{"list", "-deps", "-json", "-compiled", "-export", "-a", "-p=1", "internal/cpu"},
			[]string{"list", "-deps", "-json", "-compiled", "-export", "-p=1", "internal/cpu"}},
		{SDKGlobalsProtocol, "internal/runtime/atomic",
			[]string{"list", "-deps", "-json", "-compiled", "-export", "-a", "-p=1", "internal/runtime/atomic"},
			[]string{"list", "-deps", "-json", "-compiled", "-export", "-p=1", "internal/runtime/atomic"}},
	} {
		t.Run(row.protocol, func(t *testing.T) {
			observation := &Observation{report: Report{Protocol: row.protocol, PackagePath: row.path,
				CommandArguments: append([]string(nil), row.capture...)}}
			if got := observation.selectionArguments(); !reflect.DeepEqual(got, row.capture) {
				t.Fatal("original compiler capture must retain its complete forced-build command", got)
			}
			provider, ok := any(observation).(interface{ verificationArguments() []string })
			if !ok {
				t.Fatal("live verification still shares the forced compiler-capture command")
			}
			actual := provider.verificationArguments()
			if !reflect.DeepEqual(actual, row.live) {
				t.Fatal("live selection changed its scope or retained repeated forced compilation", actual, row.live)
			}
			actual[0] = "mutated"
			if !reflect.DeepEqual(provider.verificationArguments(), row.live) ||
				!reflect.DeepEqual(observation.selectionArguments(), row.capture) ||
				!reflect.DeepEqual(observation.report.CommandArguments, row.capture) {
				t.Fatal("live argv was cached, shared or substituted for original compiler evidence")
			}
			if row.protocol == SDKGlobalsProtocol {
				observation.report.PackagePath = "internal/cpu"
				want := append([]string(nil), row.live...)
				want[len(want)-1] = observation.report.PackagePath
				if !reflect.DeepEqual(provider.verificationArguments(), want) {
					t.Fatal("pure command construction reused mutable package scope")
				}
			}
		})
	}
}

func TestGoStaticStorageLiveSelectionRemainsAnActualOwnedCommand(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "capture.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for function, arguments := range map[string]string{
		"captureRole": "selectionArguments", "Verify": "verificationArguments",
	} {
		t.Run(function, func(t *testing.T) {
			matches := 0
			for _, declaration := range file.Decls {
				method, ok := declaration.(*ast.FuncDecl)
				if !ok || method.Name.Name != function {
					continue
				}
				ast.Inspect(method.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "run" {
						return true
					}
					receiver, ok := selector.X.(*ast.Ident)
					if !ok || receiver.Name != "o" {
						return true
					}
					matches++
					if len(call.Args) != 2 || call.Ellipsis == token.NoPos {
						t.Fatal("selection command stopped using the complete original live scope")
					}
					context, ok := call.Args[0].(*ast.Ident)
					query, queryOK := call.Args[1].(*ast.CallExpr)
					if !ok || context.Name != "ctx" || !queryOK || len(query.Args) != 0 {
						t.Fatal("selection command lost its actual context or substituted query arguments")
					}
					generator, ok := query.Fun.(*ast.SelectorExpr)
					if !ok || generator.Sel.Name != arguments {
						t.Fatal("original compiler capture and live selection must use separate command roles", arguments)
					}
					owner, ok := generator.X.(*ast.Ident)
					if !ok || owner.Name != "o" {
						t.Fatal("selection command borrowed a different observation scope")
					}
					return true
				})
			}
			if matches != 1 {
				t.Fatal("each original capture/live verification must execute its own actual owned selection command", matches)
			}
		})
	}
}
