package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestX86ScalarBitScanRuntimeNativeOwnersCannotEmulateOrSkip(t *testing.T) {
	const path = "amd64_scalar_bitscan_execution_linux_amd64_test.go"
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("required original-Go/LLVM bit-scan execution owners absent", err)
	}
	if err := x86BitScanNativeOwnerPolicy(source); err != nil {
		t.Fatal(err)
	}
}

func x86BitScanNativeOwnerPolicy(source []byte) error {
	source = normalizeNativeOwnerPolicySource(source)
	if !strings.HasPrefix(string(source), "//go:build linux && amd64\n") {
		return fmt.Errorf("required bit-scan counterparts lost their native Linux owner")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "native-owner.go", source, 0)
	if err != nil {
		return err
	}
	roots := map[string]string{
		"TestCrossLinuxRuntimeMatrixX86BitScanNativeAMD64OriginalGoAndLLVM": "amd64",
		"TestCrossLinuxRuntimeMatrixX86BitScanNative386OriginalGoAndLLVM":   "386",
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
		var gatePositions []token.Pos
		var executionPosition token.Pos
		var invalid error
		topLevel := make(map[*ast.CallExpr]bool)
		for _, statement := range fn.Body.List {
			if expression, ok := statement.(*ast.ExprStmt); ok {
				if call, ok := expression.X.(*ast.CallExpr); ok {
					topLevel[call] = true
				}
			}
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				if name, ok := value.Fun.(*ast.Ident); ok {
					if name.Name == "x87IA32RequireNativeHost" {
						gates++
						gatePositions = append(gatePositions, value.Pos())
						if !topLevel[value] {
							invalid = fmt.Errorf("native observation must run at top level")
						}
					}
					if name.Name == "x86BitScanExecuteOriginalAndLLVM" {
						executions++
						executionPosition = value.Pos()
						if !topLevel[value] {
							invalid = fmt.Errorf("native execution must run at top level")
						}
						if len(value.Args) != 3 {
							invalid = fmt.Errorf("runtime oracle lost its complete architecture")
							return false
						}
						literal, ok := value.Args[1].(*ast.BasicLit)
						if !ok || literal.Value != strconv.Quote(arch) {
							invalid = fmt.Errorf("native owner selected another architecture")
						}
					}
				}
				if name, ok := value.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(name.Sel.Name, "Skip") {
					invalid = fmt.Errorf("missing native tools or failed execution cannot skip")
				}
			case *ast.KeyValueExpr:
				if name, ok := value.Key.(*ast.Ident); ok && (name.Name == "prefix" || name.Name == "preserveArgv0") {
					invalid = fmt.Errorf("native owner inserted a guest/emulator transport")
				}
			case *ast.ReturnStmt:
				invalid = fmt.Errorf("required native owner cannot return before observation")
			case *ast.BasicLit:
				if value.Kind == token.STRING {
					literal, err := strconv.Unquote(value.Value)
					if err != nil || strings.Contains(literal, "qemu") || literal == "-exec" {
						invalid = fmt.Errorf("native owner inserted an execution fallback: %v", err)
					}
				}
			}
			return true
		})
		if invalid != nil {
			return invalid
		}
		if gates != 2 || executions != 1 {
			return fmt.Errorf("native before/after observation or whole execution absent: %s", fn.Name.Name)
		}
		if !(gatePositions[0] < executionPosition && executionPosition < gatePositions[1]) {
			return fmt.Errorf("native observation must surround the actual execution: %s", fn.Name.Name)
		}
		delete(roots, fn.Name.Name)
	}
	if len(roots) != 0 {
		return fmt.Errorf("required native denominator incomplete: %v", roots)
	}
	return nil
}

func TestX86ScalarBitScanRuntimeNativePolicyRejectsMutation(t *testing.T) {
	source, err := os.ReadFile("amd64_scalar_bitscan_execution_linux_amd64_test.go")
	if err != nil {
		t.Fatal(err)
	}
	const call = "\tx86BitScanExecuteOriginalAndLLVM(t, \"amd64\", execution)"
	const gate = "\tx87IA32RequireNativeHost(t)"
	text := string(normalizeNativeOwnerPolicySource(source))
	for name, mutation := range map[string]string{
		"missing after":     strings.Replace(text, call+"\n"+gate, call, 1),
		"both before":       strings.Replace(text, call+"\n"+gate, gate+"\n"+call, 1),
		"both after":        strings.Replace(strings.Replace(text, gate+"\n", "", 1), call+"\n"+gate, call+"\n"+gate+"\n"+gate, 1),
		"conditional after": strings.Replace(text, call+"\n"+gate, call+"\n\tif false {\n"+gate+"\n\t}", 1),
		"conditional run":   strings.Replace(text, call, "\tif false {\n"+call+"\n\t}", 1),
		"early return":      strings.Replace(text, call, "\treturn\n"+call, 1),
		"skip":              strings.Replace(text, call, "\tt.Skip(\"missing tool\")\n"+call, 1),
		"prefix":            strings.Replace(text, "{llc: llc,", "{prefix: []string{\"guest\"}, llc: llc,", 1),
		"preserve argv":     strings.Replace(text, "{llc: llc,", "{preserveArgv0: true, llc: llc,", 1),
		"wrong arch":        strings.Replace(text, call, strings.Replace(call, "amd64", "386", 1), 1),
		"wrong native tags": strings.Replace(text, "linux && amd64", "darwin && amd64", 1),
		"missing root":      strings.Replace(text, "TestCrossLinuxRuntimeMatrixX86BitScanNativeAMD64OriginalGoAndLLVM", "NoRequiredAMD64Root", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if mutation == text {
				t.Fatal("policy mutation did not change actual native owner source")
			}
			if x86BitScanNativeOwnerPolicy([]byte(mutation)) == nil {
				t.Fatal("invalid native lifecycle/transport owner accepted")
			}
		})
	}
}
