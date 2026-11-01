//go:build unix && go1.27

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalReadonlyDataAddress(t *testing.T) {
	assembly, declarations, count := fixedLocalDataAddressKernels()
	if count != 30 {
		t.Fatal("complete DATA address runtime inventory changed", count)
	}
	expected := make([]string, count)
	for index := range expected {
		// The source DATA's third qword is loaded and added to itself.
		expected[index] = "424446484a4c4e50"
	}
	fixedLocalConstantResultsRuntime(t, assembly, declarations, expected)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConstantIndex(t *testing.T) {
	cases := fixedLocalConstantIndexCases()
	if len(cases) != 30 {
		t.Fatal("complete constant index runtime inventory changed", len(cases))
	}
	var assembly, declarations strings.Builder
	assembly.WriteString(fixedLocalAddressData)
	var expected []string
	for index, row := range cases {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalConstantIndexFunction(name, row.body))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		// Indexed and fixed-address reads each sum to 19+20+22+26, plus
		// the adjacent private canary 77. The fixed tail is reset each time.
		value := "00000000000000fb"
		if row.literal {
			value = "64686c7074787c80" // Sum of the four independent source DATA qwords.
		}
		expected = append(expected, value)
	}
	fixedLocalConstantResultsRuntime(t, assembly.String(), declarations.String(), expected)
}

func fixedLocalConstantResultsRuntime(t *testing.T, assembly, declarations string, expected []string) {
	t.Helper()
	fixedLocalResultsRuntime(t, assembly, declarations, []uint64{^uint64(0)}, [][]string{expected})
}

func fixedLocalResultsRuntime(t *testing.T, assembly, declarations string, inputs []uint64, expected [][]string) {
	t.Helper()
	fixedLocalResultsRuntimeISA(t, assembly, declarations, inputs, expected, x86FloatCompareSSE)
}

func fixedLocalResultsRuntimeISA(t *testing.T, assembly, declarations string, inputs []uint64, expected [][]string, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	if len(inputs) == 0 || len(expected) != len(inputs) || len(expected[0]) == 0 {
		t.Fatal("invalid fixed-local runtime input/result inventory")
	}
	count := len(expected[0])
	var values []string
	for index, row := range expected {
		if len(row) != count {
			t.Fatal("inconsistent fixed-local runtime result count", index, len(row), count)
		}
		values = append(values, row...)
	}
	execution := x86FloatCompareRuntimeTools(t, axis)
	goAMD64FramePrepareOwnedToolCache(t)
	prefix := ""
	if strings.Contains(execution.triple, "apple") {
		prefix = "_"
	}
	var goCalls, cDeclarations, cCalls strings.Builder
	for index := 0; index < count; index++ {
		label := runtimeCAsmLabel(prefix + fmt.Sprintf("example.invalid/framefixture.Value%d", index))
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t) __asm__(%s);\n", index, label)
	}
	for _, input := range inputs {
		for index := 0; index < count; index++ {
			fmt.Fprintf(&goCalls, "fmt.Printf(\"%%016x\\n\",Value%d(uint64(0x%x)))\n", index, input)
			fmt.Fprintf(&cCalls, "printf(\"%%016llx\\n\",(unsigned long long)value%d(UINT64_C(0x%x)));\n", index, input)
		}
	}
	original := "package main\nimport \"fmt\"\n" + declarations + "func main() {\n" + goCalls.String() + "}\n"
	want := strings.Split(strings.TrimSpace(string(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original))), "\n")
	if len(want) != len(values) {
		t.Fatal("original Go fixed-local output inventory changed", len(want), len(values))
	}
	for index, value := range want {
		if value != values[index] {
			t.Fatalf("original Go kernel %d input %#x returned %s, want %s", index%count, inputs[index/count], value, values[index])
		}
	}
	driver := "#include <stdint.h>\n#include <stdio.h>\n" + runtimeCAsmLabelPreamble +
		cDeclarations.String() + "int main(void) {\n" + cCalls.String() + "return 0;\n}\n"
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly, declarations, runtime.GOOS+"/amd64", execution.triple)
	check := func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(level, func(t *testing.T) {
				input := ir
				if level == "-O2" {
					input = x86MulDivRoundOptimize(t, ir)
				}
				output := execution.compileAndRunLLVM(t, "fixed-local-results", input, driver, level)
				got := strings.Split(strings.TrimSpace(string(output)), "\n")
				if len(got) != len(want) {
					t.Fatal("LLVM fixed-local output inventory changed", len(got), len(want))
				}
				for index := range want {
					if got[index] != want[index] {
						t.Fatalf("fixed-local kernel %d input %#x: original %s, LLVM %s", index%count, inputs[index/count], want[index], got[index])
					}
				}
			})
		}
	}
	fixedLocalResultsRuntimeAPIs(t, pkg, request, file, options, assembly, check)
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("original Go and LLVM amd64 execute through Rosetta, not native x86 hardware")
	}
}

func fixedLocalResultsRuntimeAPIs(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest,
	file *File, options Options, assembly string, check func(*testing.T, string, error)) {
	t.Helper()
	apis := []string{"Translate", "Module", "GoModule"}
	if fixedLocalResultsRuntimeNeedsBinding(file, options) {
		fixedLocalFreshAPIs(t, pkg, request, options, apis, check)
	} else {
		// Ordinary sources require no private-frame observation or permission.
		// Reuse the independent original Go and C drivers with their own APIs.
		for _, api := range apis {
			t.Run(api, func(t *testing.T) {
				fixedLocalAPI(t, pkg, file, options, api, check, assembly)
			})
		}
	}
}

func fixedLocalResultsRuntimeNeedsBinding(file *File, options Options) bool {
	if file == nil || file.Arch != ArchAMD64 || len(file.Funcs) == 0 || options.NumericalReads != nil {
		return true
	}
	for _, fn := range file.Funcs {
		if fn.FrameSize != 0 || fn.x86FixedLocal != nil || fn.x86SourceStack != nil {
			return true
		}
	}
	for _, sig := range options.Sigs {
		if sig.x86FixedLocal != nil {
			return true
		}
	}
	return false
}
