package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestX86ResultGPSIMDSparseRuntimeNativeOwnerCannotEmulateOrSkip(t *testing.T) {
	const path = "x86_result_gp_simd_execution_linux_amd64_test.go"
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source = normalizeNativeOwnerPolicySource(source)
	if !strings.HasPrefix(string(source), "//go:build linux && amd64\n") {
		t.Fatal("both required runtime counterparts lost their actual native owner")
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{
		"TestCrossLinuxRuntimeMatrixX86GPSIMDSparseNativeAMD64OriginalGoAndLLVM": "amd64",
		"TestCrossLinuxRuntimeMatrixX86GPSIMDSparseNative386OriginalGoAndLLVM":   "386",
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		arch, required := roots[fn.Name.Name]
		if !required {
			continue
		}
		gates, executions := 0, 0
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				if name, ok := value.Fun.(*ast.Ident); ok {
					if name.Name == "x87IA32RequireNativeHost" {
						gates++
					}
					if name.Name == "x86GPSIMDSparseExecuteOriginalAndLLVM" {
						executions++
						if len(value.Args) != 3 {
							t.Fatal("runtime oracle lost its complete explicit architecture")
						}
						literal, ok := value.Args[1].(*ast.BasicLit)
						if !ok || literal.Value != strconv.Quote(arch) {
							t.Fatal("native owner selected another source architecture")
						}
					}
				}
				if name, ok := value.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(name.Sel.Name, "Skip") {
					t.Fatal("missing native tools or a failed owner cannot skip")
				}
			case *ast.KeyValueExpr:
				if name, ok := value.Key.(*ast.Ident); ok && (name.Name == "prefix" || name.Name == "preserveArgv0") {
					t.Fatal("native owner inserted a guest/emulator transport")
				}
			case *ast.BasicLit:
				if value.Kind == token.STRING {
					literal, err := strconv.Unquote(value.Value)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(literal, "qemu") || literal == "-exec" {
						t.Fatal("native owner inserted an execution fallback")
					}
				}
			}
			return true
		})
		if gates != 2 || executions != 1 {
			t.Fatal("required before/after native observation or whole-source execution missing", fn.Name.Name, gates, executions)
		}
		delete(roots, fn.Name.Name)
	}
	if len(roots) != 0 {
		t.Fatal("native runtime denominator is incomplete", roots)
	}
}
