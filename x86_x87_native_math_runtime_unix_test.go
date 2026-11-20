//go:build unix

package plan9asm

import (
	"bytes"
	"testing"
)

func x87NativeMathRuntime(t *testing.T, execute bool) {
	t.Helper()
	execution := fixedLocalPackedCompileOnlyTools(t)
	if execute {
		execution = x86FloatCompareExecutionTools(t)
	}
	source, declarations := x87NativeMathRuntimeProgram(t)
	goDriver, cDriver := x87NativeMathRuntimeDrivers()
	original := x86DefinedStatusBuildOriginal(t, execution, declarations, source+x86X87NativeStateAssembly("amd64"), goDriver)
	checks := len(x87NativeMathRuntimeInputs()) * 12
	var reference []byte
	if execute {
		reference = execution.run(t, original)
		if len(reference) != checks*8 {
			t.Fatal("original Go did not complete every native math input/PC/RC", len(reference), checks)
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, source, declarations, "amd64", execution.triple, api, X87Hardware)
			if err != nil || ir == "" {
				t.Fatal("complete original native math source", api, err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					if !execute {
						execution.compileLLVM(t, "native-x87-math", ir, cDriver, level)
						return
					}
					actual := execution.compileAndRunLLVM(t, "native-x87-math", ir, cDriver, level)
					if !bytes.Equal(actual, reference) {
						first := 0
						for first < len(actual) && first < len(reference) && actual[first] == reference[first] {
							first++
						}
						t.Fatalf("native math raw float64 bits differ from original Go at check %d: bytes actual=%d expected=%d", first/8, len(actual), len(reference))
					}
					t.Logf("native math original-Go/LLVM checks=%d, twelve operations and both pair outputs, PC24/53/64 and four RC, exact NaN bits included", checks)
				})
			}
		})
	}
}

func TestX86X87NativeMathOriginalGoAndLLVMObjects(t *testing.T) {
	x87NativeMathRuntime(t, false)
}
