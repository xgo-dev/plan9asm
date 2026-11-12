package plan9asm

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func x86PackedReductionNativeFunctions(path string) (map[string]*ast.FuncDecl, error) {
	syntax, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range syntax.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			if functions[function.Name.Name] != nil {
				return nil, fmt.Errorf("duplicate required native reduction function %s", function.Name.Name)
			}
			functions[function.Name.Name] = function
		}
	}
	return functions, nil
}

func TestX86PackedReductionCompleteNativeOwners(t *testing.T) {
	x86PackedReductionOriginalRuntimeProgramsUnchanged(t)
	const path = "amd64_packed_reduction_runtime_linux_amd64_test.go"
	functions, err := x86PackedReductionNativeFunctions(path)
	if err != nil {
		t.Log("required native reduction owners are missing", err)
	}
	want := make(map[string]bool)
	for _, family := range []struct{ root, driver string }{
		{"TestCrossLinuxRuntimeMatrixX86PackedReductionNativeValues", "x86PackedReductionNativeValues"},
		{"TestCrossLinuxRuntimeMatrixX86PackedReductionNativeDeadFaults", "x86PackedReductionNativeFaults"},
	} {
		for part := 0; part < 4; part++ {
			name := family.root + fmt.Sprintf("Part%d", part)
			want[name] = true
			t.Run(name, func(t *testing.T) {
				function := functions[name]
				if function == nil || function.Body == nil || len(function.Body.List) != 1 {
					t.Fatal("missing or bypassed complete native reduction owner", name)
				}
				statement, ok := function.Body.List[0].(*ast.ExprStmt)
				if !ok {
					t.Fatal("native reduction owner must execute the complete direct driver", name)
				}
				call, ok := statement.X.(*ast.CallExpr)
				if !ok {
					t.Fatal("native reduction owner omitted its execution call", name)
				}
				callee, ok := call.Fun.(*ast.Ident)
				if !ok || callee.Name != family.driver || len(call.Args) != 2 {
					t.Fatal("native reduction owner substituted a sampled or object-only driver", name)
				}
				context, ok := call.Args[0].(*ast.Ident)
				if !ok || context.Name != "t" {
					t.Fatal("native reduction owner lost the real test context", name)
				}
				partition, ok := call.Args[1].(*ast.BasicLit)
				if !ok || partition.Kind != token.INT || partition.Value != strconv.Itoa(part) {
					t.Fatal("native reduction owner borrowed another partition", name)
				}
			})
		}
	}
	for name := range functions {
		if strings.HasPrefix(name, "Test") && !want[name] {
			t.Error("unregistered native reduction owner", name)
		}
	}
	t.Run("actual_native_host_selection", func(t *testing.T) {
		for _, target := range []struct{ os, arch string }{
			{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm"}, {"linux", "arm64"},
			{"js", "wasm"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
		} {
			context := build.Default
			context.GOOS, context.GOARCH = target.os, target.arch
			selected, err := context.MatchFile(".", path)
			if err != nil || selected != (target.os == "linux" && target.arch == "amd64") {
				t.Fatal("native reduction owner lost its required matching-host selection", target, selected, err)
			}
		}
	})
}

func TestX86PackedReductionCompleteNativeDriverRequired(t *testing.T) {
	const path = "amd64_packed_reduction_native_tools_test.go"
	functions, err := x86PackedReductionNativeFunctions(path)
	if err != nil {
		t.Fatal("missing real SSE3/SSE4.1/AVX reduction execution driver", err)
	}
	for _, required := range []string{"x86PackedReductionNativeTools", "x86PackedReductionNativePipelines"} {
		if function := functions[required]; function == nil || function.Body == nil {
			t.Fatal("missing complete native reduction driver", required)
		}
	}
	function := functions["x86PackedReductionNativeTools"]
	calls := make(map[string]int)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callee, ok := call.Fun.(*ast.Ident); ok {
			calls[callee.Name]++
			if callee.Name == "x86FloatCompareRuntimeTools" {
				if len(call.Args) != 2 {
					t.Fatal("native reductions lost the actual VEX execution route")
				}
				axis, ok := call.Args[1].(*ast.Ident)
				if !ok || axis.Name != "x86FloatCompareVEX" {
					t.Fatal("SSE3/SSE4.1/AVX reductions must not require AVX512 or borrow a weaker SSE axis")
				}
			}
		}
		if callee, ok := call.Fun.(*ast.SelectorExpr); ok {
			calls[callee.Sel.Name]++
			if callee.Sel.Name == "Skip" || callee.Sel.Name == "Skipf" || callee.Sel.Name == "SkipNow" {
				t.Fatal("missing tools or CPU cannot skip a required native reduction owner")
			}
		}
		return true
	})
	for _, required := range []string{"x86PackedReductionRequireNativeHost", "x86FloatCompareRuntimeTools", "compileC", "run"} {
		if calls[required] != 1 {
			t.Fatal("native reduction driver omitted actual host/CPU/opcode execution", required, calls[required])
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"SSE3=%u SSE41=%u AVX=%u OSXSAVE=%u XCR0=%llx",
		"PACKED_REDUCTION_NATIVE_SSE3_SSE41_AVX_OK", "__get_cpuid(1", "xgetbv", "(xcr0&6)!=6",
		"dppd", "dpps", "vdppd", "vdpps", "haddps", "haddpd", "hsubps", "hsubpd",
		"vhaddps", "vhaddpd", "vhsubps", "vhsubpd", "execution.prefix", "execution.preserveArgv0",
		"backend_O0", "backend_O2", "IR_O2_backend_O2", "x86DwordProductIROptimize",
		"compileAndRunLLVM", "string(got) != string(want)",
	} {
		if !strings.Contains(string(data), required) {
			t.Fatal("native reductions omitted a CPU/opcode/pipeline obligation", required)
		}
	}
	for _, forbidden := range []string{"x86FloatCompareEVEX", "avx512", "zmm", "0xe6"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("X/Y native reduction owner improperly depends on AVX512/Z state", forbidden)
		}
	}
}
