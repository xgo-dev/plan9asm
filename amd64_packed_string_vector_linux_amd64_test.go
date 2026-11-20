//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The portable byte oracle does not execute a VEX opcode. This required native
// counterpart executes actual Go ABI0 AVX sources and both LLVM levels, with
// complete Y aliases, six flags/LAHF/index and independent input canaries.
func TestCrossLinuxRuntimeMatrixX86PackedStringImplicitVectorNativeAVX(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	execution.compiler = append(execution.compiler, "-mno-red-zone")
	execution.requireAVX(t)
	cases, declarations, source := x86PackedStringNativeYFixture()
	original := x86DefinedStatusBuildOriginal(t, execution, declarations, source, x86PackedStringNativeGoDriver(cases))
	output := execution.run(t, original)
	want := fmt.Sprintf("original native AVX packed-string observations %d failures 0\n", len(cases)*4)
	if string(output) != want {
		t.Fatalf("actual original Go AVX byte oracle: %s", output)
	}
	ir := x86CPUQueryIRFromDeclaration(t, source, declarations, "amd64", execution.triple, "Go")
	main := strings.Replace(x86PackedStringVectorCOracle(cases), "view<3", "view<2", 1)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			output := execution.compileAndRunLLVM(t, "native-packed-string-vector", input, main, level)
			want := fmt.Sprintf("portable packed-string byte observations %d failures 0\n", len(cases)*4)
			if string(output) != want {
				t.Fatalf("native LLVM AVX byte oracle: %s", output)
			}
		})
	}
}
