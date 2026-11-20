package plan9asm

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func TestX86COMIRequiredNativeRuntimeOwners(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	selector, err := x86FloatCompareLinuxCISelector(string(workflow))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []struct {
		path   string
		tagged bool
		owners map[string]struct {
			calls map[string]string
			axis  string
		}
	}{
		{"amd64_comi_runtime_linux_amd64_test.go", false, map[string]struct {
			calls map[string]string
			axis  string
		}{
			"TestCrossLinuxRuntimeMatrixX86COMINativeVectorFlags": {map[string]string{
				"x86ScalarCompareAFOriginalGo": "x86FloatCompareVEX", "x86ScalarCompareAFLLVM": "x86FloatCompareVEX",
			}, "VEX"},
			"TestCrossLinuxRuntimeMatrixX86COMINativeVectorMXCSR": {map[string]string{
				"x86COMIOriginalConstantsAndMXCSR": "x86FloatCompareVEX",
			}, "VEX"},
		}},
		{"amd64_comi_native_avx512_linux_amd64_test.go", true, map[string]struct {
			calls map[string]string
			axis  string
		}{
			"TestCrossLinuxRuntimeMatrixX86COMIRawNativeCompare":     {map[string]string{"x86COMIRawNativeCompare": ""}, ""},
			"TestCrossLinuxRuntimeMatrixX86COMINativeDeadExceptions": {map[string]string{"x86COMIDeadFaults": "true"}, ""},
			"TestCrossLinuxRuntimeMatrixX86COMINativeVectorFlagsEVEX": {map[string]string{
				"x86ScalarCompareAFOriginalGo": "x86FloatCompareEVEX", "x86ScalarCompareAFLLVM": "x86FloatCompareEVEX",
			}, "EVEX"},
			"TestCrossLinuxRuntimeMatrixX86COMINativeVectorMXCSREVEX": {map[string]string{
				"x86COMIOriginalConstantsAndMXCSR": "x86FloatCompareEVEX",
			}, "EVEX"},
		}},
	} {
		for _, target := range []struct{ os, arch string }{
			{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm64"},
			{"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
		} {
			for _, qualified := range []bool{false, true} {
				ctx := build.Default
				ctx.GOOS, ctx.GOARCH = target.os, target.arch
				ctx.BuildTags = nil
				if qualified {
					ctx.BuildTags = []string{"plan9asm_native_avx512"}
				}
				matched, err := ctx.MatchFile(".", source.path)
				want := target.os == "linux" && target.arch == "amd64" && (!source.tagged || qualified)
				if err != nil || matched != want {
					t.Fatal("COMI ISA ownership changed", source.path, target, qualified, matched, err)
				}
			}
		}
		file, err := parser.ParseFile(token.NewFileSet(), source.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			expected, known := source.owners[fn.Name.Name]
			if !known || !selector.MatchString(fn.Name.Name) {
				t.Fatal("unexpected or unselected native owner", fn.Name.Name)
			}
			delete(source.owners, fn.Name.Name)
			actual, runs := make(map[string]string), 0
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.IfStmt, *ast.ReturnStmt, *ast.ForStmt, *ast.RangeStmt, *ast.BranchStmt:
					t.Fatal("native owner cannot conditionally skip or truncate its fixture", fn.Name.Name)
				case *ast.CallExpr:
					if method, ok := node.Fun.(*ast.SelectorExpr); ok {
						receiver, owned := method.X.(*ast.Ident)
						if !owned || receiver.Name != "t" || method.Sel.Name != "Run" || len(node.Args) != 2 {
							t.Fatal("native owner cannot replace execution with skip/log helpers", fn.Name.Name)
						}
						literal, ok := node.Args[0].(*ast.BasicLit)
						if !ok {
							t.Fatal("native ISA child must be explicit", fn.Name.Name)
						}
						axis, err := strconv.Unquote(literal.Value)
						if err != nil || axis != expected.axis {
							t.Fatal("native ISA child changed", fn.Name.Name, axis, err)
						}
						runs++
						return true
					}
					callee, ok := node.Fun.(*ast.Ident)
					if !ok {
						return true
					}
					argument, known := expected.calls[callee.Name]
					if !known || len(node.Args) != 1 && len(node.Args) != 2 {
						t.Fatal("unknown native fixture call", callee.Name)
					}
					owner, ok := node.Args[0].(*ast.Ident)
					if !ok || owner.Name != "t" {
						t.Fatal("native fixture lost its test owner")
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
			if !reflect.DeepEqual(actual, expected.calls) || (runs == 1) != (expected.axis != "") || runs > 1 {
				t.Fatal("incomplete native fixture dispatch", fn.Name.Name, actual, runs)
			}
		}
		if len(source.owners) != 0 {
			t.Fatal("native COMI execution owners missing", source.owners)
		}
	}
}
