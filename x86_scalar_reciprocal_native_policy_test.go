package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func TestX86ScalarReciprocalNativeCommandsRetainExactOwnedHelpers(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "x86_scalar_reciprocal_native_runtime_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]int{
		"goAssemblerOracleOutput": 1, "x86ScalarFPBitViewAPI": 1, "x86DwordProductIROptimize": 1,
		"execution.compileLLVM": 2, "execution.run": 1, "x87IA32RunDirect": 1,
		"x86NativeOracleIA32Executable": 2, "x86ObserveMemoryFault": 1, "x86RunOriginalGoNativeSource": 1,
	}
	if err := x86CheckHalfIndirectCommandOwner(file, "x86RunScalarReciprocalNative", required); err != nil {
		t.Fatal(err)
	}
	for name := range required {
		changed := make(map[string]int)
		for name, count := range required {
			changed[name] = count
		}
		changed[name]++
		if err := x86CheckHalfIndirectCommandOwner(file, "x86RunScalarReciprocalNative", changed); err == nil {
			t.Fatal("policy accepted a missing or duplicate bounded execution edge", name)
		}
	}

	// Linux-only roots are parsed even on ARM64 developer hosts. In particular,
	// a valid Go object or a cross-process emulator cannot replace actual native
	// host bracketing and the AVX OS-state permission probe.
	file, err = parser.ParseFile(token.NewFileSet(), "x86_scalar_reciprocal_native_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"AMD64", "386"} {
		root := "TestCrossLinuxRuntimeMatrixX86ScalarReciprocalOriginalGoAndNative" + suffix
		var observed = make(map[string]int)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != root {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if name, ok := call.Fun.(*ast.Ident); ok {
					observed[name.Name]++
				} else if method, ok := call.Fun.(*ast.SelectorExpr); ok {
					if receiver, ok := method.X.(*ast.Ident); ok {
						observed[receiver.Name+"."+method.Sel.Name]++
					}
				}
				return true
			})
		}
		expected := map[string]int{"x87IA32RequireNativeHost": 2, "execution.requireAVX": 1, "x86RunScalarReciprocalNative": 1}
		if suffix == "AMD64" {
			expected["x86FloatCompareExecutionTools"] = 1
		} else {
			expected["findLLVM22Tool"], expected["exec.LookPath"], expected["t.Fatalf"] = 1, 1, 1
		}
		if !reflect.DeepEqual(observed, expected) {
			t.Fatal("native owner lost exact host/tool/preflight/bounded driver edges", root, observed, expected)
		}
	}
}
