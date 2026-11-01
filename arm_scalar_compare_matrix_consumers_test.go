package plan9asm

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestARMScalarCompareTypedGoMatrixObjects(t *testing.T) {
	forms := append(armCompareMatrixBanks(), armCompareMatrixConditions()...)
	if len(forms) != 548 {
		t.Fatalf("incomplete typed Go compare forms: %d", len(forms))
	}
	source, _ := armCompareMatrixSource(forms, false)
	source = strings.ReplaceAll(source, "TEXT ", "TEXT ·")
	var declarations strings.Builder
	declarations.WriteString("package compare\n")
	for index := range forms {
		fmt.Fprintf(&declarations, "func matrixCompare%d(input *[65]uint32, output *[69]uint32, status uint32)\n", index)
	}
	pkg := mustGoPackage(t, "example.com/compare", declarations.String())
	requireARMGoAssemblerResult(t, source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, target := range []struct{ os, triple string }{
		{"linux", "armv5te-unknown-linux-gnueabi"},
		{"linux", "armv6-unknown-linux-gnueabihf"},
		{"linux", "armv7-unknown-linux-gnueabihf"},
		{"windows", "thumbv7-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: target.os, GOARCH: "arm", TargetTriple: target.triple,
			})
			if err != nil {
				t.Fatal(err)
			}
			ir := translated.Module.String()
			translated.Module.Dispose()
			if len(translated.Functions) != len(forms) || len(translated.Signatures) != len(forms) {
				t.Fatalf("typed declarations lost compare forms: functions=%d signatures=%d", len(translated.Functions), len(translated.Signatures))
			}
			if count := strings.Count(ir, `asm sideeffect "vcmp`); count != len(forms) {
				t.Fatalf("typed Go route lost native effects: got %d want %d", count, len(forms))
			}
			compileLLVMToObject(t, llc, target.triple, "arm-compare-typed-go.ll", "arm-compare-typed-go.o", ir)
		})
	}
}

func TestARMScalarCompareRequiredRuntimeOwner(t *testing.T) {
	const file = "arm_scalar_compare_full_matrix_runtime_linux_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "arm"},
		{"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"js", "wasm"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", file)
		if err != nil || selected != (target.os == "linux") {
			t.Fatal("required compare runtime source selection", target, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]bool{
		"TestCrossLinuxRuntimeMatrixARMScalarCompareFullMatrix": {
			"requireARMScalarRuntime": false,
			"armCompareMatrixBanks":   false, "armCompareMatrixStates": false,
			"armCompareMatrixConditions": false, "runARMCompareMatrixBatch": false,
		},
		"runARMCompareMatrixBatch": {
			"requireARMScalarRuntime": false, "armConversionGoObservations": false,
			"armCompareMatrixTranslate": false, "armFloatEffectOptimizedIR": false,
			"compileAndRunRuntimeTestWithCompiler": false,
		},
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		required, found := want[function.Name.Name]
		if !found {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(selector.Sel.Name, "Skip") {
				t.Errorf("required runtime owner contains a local skip: %s", function.Name.Name)
			}
			if name, ok := call.Fun.(*ast.Ident); ok {
				if _, found := required[name.Name]; found {
					required[name.Name] = true
				}
			}
			return true
		})
	}
	for function, required := range want {
		for name, found := range required {
			if !found {
				t.Errorf("required runtime owner %s lost %s", function, name)
			}
		}
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") || !strings.Contains(string(workflow), "PLAN9ASM_CROSS_EXEC: '1'") {
		t.Fatal("CI no longer selects and enables the mandatory native runtime owner", err)
	}
}
