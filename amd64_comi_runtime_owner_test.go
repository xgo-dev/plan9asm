package plan9asm

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"testing"
)

func TestX86COMIRequiredNativeRuntimeOwners(t *testing.T) {
	const path = "amd64_comi_runtime_linux_amd64_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH = target.os, target.arch
		matched, err := ctx.MatchFile(".", path)
		if err != nil || matched != (target.os == "linux" && target.arch == "amd64") {
			t.Fatal("native COMI runtime owner selection changed", target, matched, err)
		}
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	selector, err := x86FloatCompareLinuxCISelector(string(workflow))
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"TestCrossLinuxRuntimeMatrixX86COMIRawNativeCompare":     {"x86COMIRawNativeCompare": ""},
		"TestCrossLinuxRuntimeMatrixX86COMINativeDeadExceptions": {"x86COMIDeadFaults": "true"},
		"TestCrossLinuxRuntimeMatrixX86COMINativeVectorFlags": {
			"x86ScalarCompareAFOriginalGo": "axis", "x86ScalarCompareAFLLVM": "axis",
		},
		"TestCrossLinuxRuntimeMatrixX86COMINativeVectorMXCSR": {"x86COMIOriginalConstantsAndMXCSR": "axis"},
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		expected, known := want[fn.Name.Name]
		if !known || !selector.MatchString(fn.Name.Name) {
			t.Fatal("unexpected or unselected native owner", fn.Name.Name)
		}
		delete(want, fn.Name.Name)
		actual, ranges := make(map[string]string), 0
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.IfStmt, *ast.ReturnStmt, *ast.ForStmt, *ast.BranchStmt:
				t.Fatal("native owner cannot conditionally skip or truncate its fixture", fn.Name.Name)
			case *ast.RangeStmt:
				ranges++
				values, ok := node.X.(*ast.CompositeLit)
				if !ok || len(values.Elts) != 2 {
					t.Fatal("native vector owner lost exhaustive VEX/EVEX axes")
				}
				for index, name := range []string{"x86FloatCompareVEX", "x86FloatCompareEVEX"} {
					value, ok := values.Elts[index].(*ast.Ident)
					if !ok || value.Name != name {
						t.Fatal("native vector owner changed ISA selection", fn.Name.Name)
					}
				}
			case *ast.CallExpr:
				if method, ok := node.Fun.(*ast.SelectorExpr); ok && method.Sel.Name != "Run" {
					t.Fatal("native owner must not replace execution with skip/log helpers", fn.Name.Name)
				}
				callee, ok := node.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				argument, known := expected[callee.Name]
				if !known || len(node.Args) != 1 && len(node.Args) != 2 {
					t.Fatal("unknown native fixture call", callee.Name)
				}
				got := ""
				if len(node.Args) == 2 {
					value, ok := node.Args[1].(*ast.Ident)
					if !ok {
						t.Fatal("native fixture lost explicit native/ISA argument")
					}
					got = value.Name
				}
				if _, duplicate := actual[callee.Name]; duplicate || got != argument {
					t.Fatal("duplicated or weakened native fixture", callee.Name, got)
				}
				actual[callee.Name] = got
			}
			return true
		})
		vector := false
		for _, argument := range expected {
			vector = vector || argument == "axis"
		}
		if !reflect.DeepEqual(actual, expected) || (ranges == 1) != vector || ranges > 1 {
			t.Fatal("incomplete native fixture dispatch", fn.Name.Name, actual, ranges)
		}
	}
	if len(want) != 0 {
		t.Fatal("native COMI execution owners missing", want)
	}
}
