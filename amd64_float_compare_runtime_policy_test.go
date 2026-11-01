package plan9asm

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestX86FloatingCompareRuntimeRetainsOptimizationLevels(t *testing.T) {
	// The old shared helper omitted -O, whose llc default is O2. Explicit
	// transport must preserve that level, rather than weaken the numerical gate.
	for _, fixture := range []struct{ file, program string }{
		{"amd64_conformance_test.go", "amd64_conformance"},
		{"amd64_float_compare_numerical_test.go", "compare-ieee"},
		{"amd64_float_compare_fp_runtime_test.go", "compare-fp-scalar-bytes"},
		{"amd64_float_compare_regression_test.go", "floating-compare-legacy-alias"},
		{"amd64_lower_convert_double_dword_test.go", "packed_double_dword"},
		{"amd64_lower_convert_double_dword_test.go", "raw_packed_double_dword"},
		{"amd64_insert_extract_native_runtime_test.go", "masked-native-extract"},
	} {
		t.Run(fixture.program, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), fixture.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			matches := 0
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 5 {
					return true
				}
				callee, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || callee.Sel.Name != "compileAndRunLLVM" {
					return true
				}
				name, ok := call.Args[1].(*ast.BasicLit)
				if !ok || name.Kind != token.STRING {
					return true
				}
				program, err := strconv.Unquote(name.Value)
				if err != nil || program != fixture.program {
					return true
				}
				matches++
				level, ok := call.Args[4].(*ast.BasicLit)
				if !ok || level.Kind != token.STRING || level.Value != `"-O2"` {
					t.Error("ordinary numerical runtime must retain explicit llc O2")
				}
				return true
			})
			if matches != 1 {
				t.Fatalf("expected one actual numerical consumer, found %d", matches)
			}
		})
	}
}

func TestX86FloatingCompareRuntimeRequiresExplicitISAAxes(t *testing.T) {
	for _, fixture := range []struct{ file, root, helper, axis string }{
		{"amd64_float_compare_fp_runtime_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpans", "x86FloatCompareFPScalarByteSpansRuntime", "x86FloatCompareSSE"},
		{"amd64_float_compare_numerical_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSR", "x86FloatCompareIndependentRuntime", "x86FloatCompareSSE"},
		{"amd64_float_compare_numerical_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffects", "x86FloatCompareDeadResultRuntime", "x86FloatCompareSSE"},
		{"amd64_float_compare_runtime_linux_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpansVEX", "x86FloatCompareFPScalarByteSpansRuntime", "x86FloatCompareVEX"},
		{"amd64_float_compare_runtime_linux_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSRVEX", "x86FloatCompareIndependentRuntime", "x86FloatCompareVEX"},
		{"amd64_float_compare_runtime_linux_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffectsVEX", "x86FloatCompareDeadResultRuntime", "x86FloatCompareVEX"},
		{"amd64_float_compare_runtime_linux_amd64_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpansEVEX", "x86FloatCompareFPScalarByteSpansRuntime", "x86FloatCompareEVEX"},
		{"amd64_float_compare_runtime_linux_amd64_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSREVEX", "x86FloatCompareIndependentRuntime", "x86FloatCompareEVEX"},
		{"amd64_float_compare_runtime_linux_amd64_test.go", "TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffectsEVEX", "x86FloatCompareDeadResultRuntime", "x86FloatCompareEVEX"},
	} {
		t.Run(fixture.root, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), fixture.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			var body *ast.BlockStmt
			for _, declaration := range file.Decls {
				if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == fixture.root {
					body = fn.Body
				}
			}
			if body == nil || len(body.List) != 1 {
				t.Fatal("required runtime root must directly consume its complete explicit ISA fixture")
			}
			statement, ok := body.List[0].(*ast.ExprStmt)
			if !ok {
				t.Fatal("required runtime root cannot return or substitute a skip")
			}
			call, ok := statement.X.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				t.Fatal("required runtime fixture must receive the explicit ISA axis")
			}
			callee, ok := call.Fun.(*ast.Ident)
			axis, axisOK := call.Args[1].(*ast.Ident)
			if !ok || callee.Name != fixture.helper || !axisOK || axis.Name != fixture.axis {
				t.Fatalf("required runtime root does not consume %s with %s", fixture.helper, fixture.axis)
			}
		})
	}
}

func TestX86FloatingCompareRequiredLinuxBuildSelection(t *testing.T) {
	for _, target := range []struct{ os, arch string }{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"windows", "amd64"}} {
		for _, file := range []string{"amd64_float_compare_runtime_linux_test.go", "amd64_float_compare_runtime_linux_amd64_test.go", "amd64_insert_extract_native_runtime_linux_amd64_test.go", "amd64_packed_double_dword_native_linux_amd64_test.go"} {
			ctx := build.Default
			ctx.GOOS, ctx.GOARCH = target.os, target.arch
			actual, err := ctx.MatchFile(".", file)
			if err != nil {
				t.Fatal(err)
			}
			want := target.os == "linux" && (target.arch == "amd64" || file == "amd64_float_compare_runtime_linux_test.go" && target.arch == "arm64")
			if actual != want {
				t.Fatalf("%s on %s/%s selected=%v want=%v", file, target.os, target.arch, actual, want)
			}
		}
	}
	contents, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	selector, err := x86FloatCompareLinuxCISelector(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	for _, axis := range []string{"VEX", "EVEX"} {
		for _, family := range []string{"FPScalarByteSpans", "IndependentIEEEAndMXCSR", "DeadResultEffects"} {
			if !selector.MatchString("TestCrossLinuxRuntimeMatrixX86FloatingCompare" + family + axis) {
				t.Fatal("required Linux CI does not select complete compare fixture", family, axis)
			}
		}
	}
	if !selector.MatchString("TestCrossLinuxRuntimeMatrixAMD64ConformanceNativeAVX512") {
		t.Fatal("required Linux CI does not select original-Go/LLVM native wide conformance")
	}
	if !selector.MatchString("TestCrossLinuxRuntimeMatrixX86InsertExtractMaskedNativeMemory") {
		t.Fatal("required Linux CI does not select all masked native memory extract cases")
	}
	if !selector.MatchString("TestCrossLinuxRuntimeMatrixAMD64PackedDoubleDwordNativeAVX512") {
		t.Fatal("required Linux CI does not select complete named/raw original-Go/LLVM double/dword conversions")
	}
}

func x86FloatCompareLinuxCISelector(workflow string) (*regexp.Regexp, error) {
	job, found := ciWorkflowJob(workflow, "cross-runtime")
	if !found || !strings.Contains(job, "ubuntu-latest") {
		return nil, fmt.Errorf("required Linux native AMD64 runtime job is absent")
	}
	// CI now uses exhaustive owners, not the previous single go-test command.
	// Match the actual runner invocation only inside this exact job; an
	// aggregate's selector or a commented command cannot replace execution.
	command := regexp.MustCompile(`(?m)^          go run \./cmd/plan9asmtest [^\r\n]+\\\r?\n[ \t]+-ci-selector '([^']+)'[ \t]+\\`)
	matches := command.FindAllStringSubmatch(job, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf("required Linux runtime has %d actual partition selectors, want one", len(matches))
	}
	selector, err := regexp.Compile(matches[0][1])
	if err != nil {
		return nil, fmt.Errorf("invalid actual Linux runtime selector: %w", err)
	}
	return selector, nil
}

func TestX86FloatingCompareLinuxCISelectorCannotBorrowAnotherJob(t *testing.T) {
	contents, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	// ciWorkflowJob accepts LF and CRLF but returns an LF job. Keep the
	// mutation input in the same representation, then exercise both formats.
	workflow := strings.ReplaceAll(string(contents), "\r\n", "\n")
	job, found := ciWorkflowJob(workflow, "cross-runtime")
	if !found {
		t.Fatal("original cross-runtime job is missing")
	}
	for _, source := range []string{workflow, strings.ReplaceAll(workflow, "\n", "\r\n")} {
		if _, err := x86FloatCompareLinuxCISelector(source); err != nil {
			t.Fatal(err)
		}
	}
	for _, mutation := range []struct {
		name string
		edit func(string) string
	}{
		{"different_job", func(text string) string {
			return strings.Replace(text, "\n  cross-runtime:\n", "\n  removed-runtime:\n", 1)
		}},
		{"aggregate_only_selector", func(text string) string {
			changed := strings.Replace(job, "-ci-selector", "-removed-selector", 1)
			return strings.Replace(text, job, changed, 1)
		}},
		{"commented_command", func(text string) string {
			return strings.Replace(text, "          go run ./cmd/plan9asmtest -out _out/cross-runtime-owner",
				"          # go run ./cmd/plan9asmtest -out _out/cross-runtime-owner", 1)
		}},
		{"non_linux_host", func(text string) string {
			changed := strings.Replace(job, "ubuntu-latest", "windows-latest", 1)
			return strings.Replace(text, job, changed, 1)
		}},
		{"invalid_expression", func(text string) string {
			changed := regexp.MustCompile(`-ci-selector '[^']+'`).ReplaceAllString(job, "-ci-selector '['")
			return strings.Replace(text, job, changed, 1)
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := mutation.edit(workflow)
			if changed == workflow {
				t.Fatal("mutation did not change the actual workflow")
			}
			for _, source := range []string{changed, strings.ReplaceAll(changed, "\n", "\r\n")} {
				if _, err := x86FloatCompareLinuxCISelector(source); err == nil {
					t.Fatal("absent, foreign or invalid runtime execution was accepted")
				}
			}
		})
	}
}

func TestAMD64ConformanceWideRuntimeIsRequired(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_float_compare_runtime_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == "TestCrossLinuxRuntimeMatrixAMD64ConformanceNativeAVX512" {
			body = fn.Body
		}
	}
	if body == nil || len(body.List) != 3 {
		t.Fatal("original Go and LLVM wide conformance must both consume required native preflight")
	}
	assignment, ok := body.List[0].(*ast.AssignStmt)
	if !ok || len(assignment.Rhs) != 1 {
		t.Fatal("native wide preflight is missing")
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		t.Fatal("native wide preflight must bind the explicit EVEX execution axis")
	}
	callee, ok := call.Fun.(*ast.Ident)
	axis, axisOK := call.Args[1].(*ast.Ident)
	if !ok || callee.Name != "x86FloatCompareRuntimeTools" || !axisOK || axis.Name != "x86FloatCompareEVEX" {
		t.Fatal("native wide conformance cannot borrow ordinary/guest tools")
	}
	for index, name := range []string{"amd64ConformanceOriginalWideGo", "amd64ConformanceLLVMRuntime"} {
		statement, ok := body.List[index+1].(*ast.ExprStmt)
		if !ok {
			t.Fatal("native wide conformance cannot substitute an early return or skip")
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok {
			t.Fatal("native wide conformance is not consumed")
		}
		callee, ok := call.Fun.(*ast.Ident)
		if !ok || callee.Name != name || len(call.Args) < 2 {
			t.Fatal("native wide conformance consumer is missing", name)
		}
		tools, ok := call.Args[1].(*ast.Ident)
		if !ok || tools.Name != "execution" {
			t.Fatal("native wide conformance dropped its validated execution route")
		}
		if index == 1 {
			if len(call.Args) != 3 {
				t.Fatal("native wide LLVM conformance must execute its full wide assertions")
			}
			wide, ok := call.Args[2].(*ast.Ident)
			if !ok || wide.Name != "true" {
				t.Fatal("native wide LLVM conformance was disabled")
			}
		}
	}
}
