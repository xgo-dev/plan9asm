//go:build unix && go1.27

package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalImplicitMultiplyPrivateLeafObjects(t *testing.T) {
	fixedLocalImplicitMultiplyObjects(t, true)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalImplicitMultiply(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	t.Setenv("GOCACHE", t.TempDir())
	assembly, declarations, original, driver := fixedLocalImplicitMultiplyProgram(execution.triple, true)
	want := strings.Split(strings.TrimSpace(string(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original))), "\n")
	if len(want) != 36*16*5 {
		t.Fatalf("original Go produced %d rows, want 36 kernels x 16 inputs x 5 observations", len(want))
	}
	pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, runtime.GOOS+"/amd64", execution.triple)
	fixedLocalConversionPrepareToolCache(t, request)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, ir)
					}
					output := execution.compileAndRunLLVM(t, "private-implicit-multiply", input, driver, level)
					got := strings.Split(strings.TrimSpace(string(output)), "\n")
					if len(got) != len(want) {
						t.Fatalf("LLVM row count = %d, original = %d", len(got), len(want))
					}
					for index := range want {
						if got[index] != want[index] {
							t.Fatalf("private multiply halves/FLAGS/canary row %d: original %s; LLVM %s", index, want[index], got[index])
						}
					}
				})
			}
		})
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("original Go and LLVM amd64 execution via Rosetta, not native x86 hardware")
	}
}
