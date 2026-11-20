package plan9asm

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

// The shared compare helper covers text, caller-owned context and typed Go.
// Explicitly add the public module-owned-context API; none is a substitute for
// another API. Callers consume all four outputs and dispose each LLVM owner.
func arm64BinaryMatrixIRs(t *testing.T, source, declarations, triple string) []string {
	t.Helper()
	irs := arm64CompareMatrixIRs(t, source, declarations, triple)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "compare", declarations)
	sizes := types.SizesFor("gc", "arm64")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	module, err := TranslateModule(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve})
	if err != nil {
		t.Fatal(err)
	}
	irs = append(irs, module.String())
	module.Dispose()
	return irs
}

func arm64BinaryTargetAPI(t *testing.T, api, source, triple string) (bool, error) {
	t.Helper()
	if api != "owned-module" {
		return arm64CompareTargetAPI(t, api, source, triple)
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return false, err
	}
	module, err := TranslateModule(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"comparison": {Name: "comparison", Ret: Void}},
	})
	present := !module.IsNil()
	if present {
		module.Dispose()
	}
	return present, err
}

func TestARM64ScalarBinaryRuntimeOwnership(t *testing.T) {
	if len(arm64BinaryStateCases()) != 157 {
		t.Fatal("complete scalar binary runtime forms changed")
	}
	for _, bits := range []int{16, 32, 64} {
		if len(arm64BinarySamples(bits, true)) != 560 || len(arm64BinarySamples(bits, false)) != 2 {
			t.Fatal("complete runtime control/input denominator changed")
		}
	}
	const filename = "arm64_scalar_binary_runtime_linux_test.go"
	for _, target := range []struct{ os, arch string }{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"js", "wasm"}} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", filename)
		if err != nil || selected != (target.os == "linux") {
			t.Fatal("required runtime source role changed", target, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"TestCrossLinuxRuntimeMatrixARM64ScalarBinaryDeadNative":      "arm64ScalarBinaryDeadRuntime",
		"TestCrossLinuxRuntimeMatrixARM64ScalarBinaryFullStateNative": "arm64BinaryStateRuntime",
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		helper, required := want[function.Name.Name]
		if !required {
			continue
		}
		calls := 0
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == helper {
				calls++
				if helper == "arm64BinaryStateRuntime" {
					last, ok := call.Args[len(call.Args)-1].(*ast.Ident)
					if !ok || last.Name != "true" {
						t.Error("required owner lost actual NEP/AH semantic effects")
					}
				}
			}
			return true
		})
		if calls != 1 {
			t.Fatalf("owner %s lost helper %s", function.Name.Name, helper)
		}
		delete(want, function.Name.Name)
	}
	if len(want) != 0 {
		t.Fatal("required Linux runtime roots absent", want)
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") || !strings.Contains(string(workflow), "PLAN9ASM_CROSS_EXEC: '1'") {
		t.Fatal("CI lost mandatory scalar binary runtime selection", err)
	}
}
