package plan9asm

import (
	"crypto/sha256"
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

func x86PackedConversionRuntimeFunctions(t *testing.T, path string) map[string]*ast.FuncDecl {
	t.Helper()
	syntax, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal("missing required complete native conversion owner or driver", path, err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range syntax.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			if functions[function.Name.Name] != nil {
				t.Fatal("duplicate complete native conversion function", function.Name.Name)
			}
			functions[function.Name.Name] = function
		}
	}
	return functions
}

func x86PackedConversionOriginalCProgramUnchanged(t *testing.T) {
	t.Helper()
	functions := x86PackedConversionRuntimeFunctions(t, "amd64_lower_packed_numeric_conversion_test.go")
	function := functions["amd64PackedNumericConversionNativeRuntimeSemantics"]
	if function == nil || function.Body == nil {
		t.Fatal("missing original independent native C program")
	}
	want := map[string]string{
		"source": "35a753aaa54d59683eed39625574d35e24d342cc53a91ceceb998c17a36d7175",
		"mainC":  "08481b19c5e80e7b2da8c77268fa37e486991839b06c9cd37efc22c6e727d43b",
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
			return true
		}
		expected, found := want[spec.Names[0].Name]
		if !found {
			return true
		}
		literal, ok := spec.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatal("original independent source/reference was replaced", spec.Names[0].Name)
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256([]byte(value))) != expected {
			t.Fatal("original complete assembly or independent C reference changed", spec.Names[0].Name, err)
		}
		delete(want, spec.Names[0].Name)
		return true
	})
	if len(want) != 0 {
		t.Fatal("original source/reference literal disappeared", want)
	}
}

func TestX86PackedConversionCompleteNativeRuntimeOwnership(t *testing.T) {
	x86PackedConversionOriginalCProgramUnchanged(t)
	const path = "amd64_packed_conversion_runtime_linux_amd64_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm"}, {"linux", "arm64"},
		{"js", "wasm"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", path)
		if err != nil || selected != (target.os == "linux" && target.arch == "amd64") {
			t.Fatal("required conversion owner lost its actual native selection", target, selected, err)
		}
	}
	functions := x86PackedConversionRuntimeFunctions(t, path)
	want := make(map[string]bool)
	for _, family := range []struct{ root, driver string }{
		{"TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512Status", "x86PackedConversionCompleteNativeValues"},
		{"TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaults", "x86PackedConversionCompleteNativeFaults"},
		{"TestCrossLinuxRuntimeMatrixX86PackedConversionNativeIndependentC", "amd64PackedNumericConversionNativeRuntimeSemantics"},
	} {
		parts := 8
		if family.driver == "amd64PackedNumericConversionNativeRuntimeSemantics" {
			parts = 1
		}
		for part := 0; part < parts; part++ {
			name := family.root
			if part != 0 {
				name += fmt.Sprintf("Part%d", part)
			}
			want[name] = true
			t.Run(name, func(t *testing.T) {
				function := functions[name]
				if function == nil || function.Body == nil || len(function.Body.List) != 1 {
					t.Fatal("missing or bypassed complete native conversion partition", name)
				}
				statement, ok := function.Body.List[0].(*ast.ExprStmt)
				if !ok {
					t.Fatal("required native partition does not execute its real driver", name)
				}
				call, ok := statement.X.(*ast.CallExpr)
				if !ok {
					t.Fatal("native partition lost its complete direct call", name)
				}
				callee, ok := call.Fun.(*ast.Ident)
				arguments := 2
				if parts == 1 {
					arguments = 1
				}
				if !ok || callee.Name != family.driver || len(call.Args) != arguments {
					t.Fatal("native partition did not consume the complete 42-member driver", name)
				}
				argument, ok := call.Args[0].(*ast.Ident)
				if !ok || argument.Name != "t" {
					t.Fatal("native partition lost its actual test context", name)
				}
				if parts != 1 {
					literal, ok := call.Args[1].(*ast.BasicLit)
					if !ok || literal.Kind != token.INT || literal.Value != strconv.Itoa(part) {
						t.Fatal("native partition borrowed another slice or a sampled subset", name)
					}
				}
			})
		}
	}
	if len(want) != 17 {
		t.Fatal("missing complete status/fault/native-C owner inventory")
	}
	for name := range functions {
		if strings.HasPrefix(name, "Test") && !want[name] {
			t.Fatal("unregistered native conversion partition", name)
		}
	}
}

func TestX86PackedConversionCompleteNativeCPUDriverRequired(t *testing.T) {
	const path = "amd64_packed_conversion_native_tools_test.go"
	functions := x86PackedConversionRuntimeFunctions(t, path)
	function := functions["x86PackedConversionNativeTools"]
	if function == nil || function.Body == nil {
		t.Fatal("complete conversions require a real F/DQ/BW/VL and native-host owner")
	}
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
					t.Fatal("native conversion owner lost the real EVEX execution route")
				}
				axis, ok := call.Args[1].(*ast.Ident)
				if !ok || axis.Name != "x86FloatCompareEVEX" {
					t.Fatal("native conversion owner substituted an SSE/emulator route")
				}
			}
		}
		if callee, ok := call.Fun.(*ast.SelectorExpr); ok {
			calls[callee.Sel.Name]++
			if callee.Sel.Name == "Skip" || callee.Sel.Name == "Skipf" || callee.Sel.Name == "SkipNow" {
				t.Fatal("missing native hardware cannot become a successful skipped conversion owner")
			}
		}
		return true
	})
	for _, required := range []string{"x86PackedConversionRequireNativeHost", "x86FloatCompareRuntimeTools", "compileC", "run"} {
		if calls[required] != 1 {
			t.Fatal("native conversion owner omitted an actual host/CPU/opcode execution check", required, calls[required])
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"AVX512F=%u AVX512DQ=%u AVX512BW=%u AVX512VL=%u OSXSAVE=%u XCR0=%llx",
		"PACKED_CONVERSION_NATIVE_F_DQ_BW_VL_OK", "__get_cpuid_count(7,0", "xgetbv",
		"vcvtqq2pd", "vcvtdq2ps", "kmovq", "0xe6",
	} {
		if !strings.Contains(string(data), required) {
			t.Fatal("complete native CPU/opcode preflight missing", required)
		}
	}
}
