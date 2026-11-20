package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixX86MMXStreamingOriginalAndLLVM(t *testing.T) {
	declarations, source, c, tests := x86MMXStreamingOracleSources()
	t.Run("original-go", func(t *testing.T) {
		x86PackedIntegerCompareRunOriginalGo(t, declarations, source, tests)
	})
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations[len("package oracle\n"):],
		"amd64", "x86_64-unknown-linux-gnu", "Go")
	if err != nil {
		t.Fatal("complete original streaming source lost its native MMX binding", err)
	}
	execution := x86FloatCompareExecutionTools(t)
	for _, passes := range []string{"default", "O2"} {
		text := ir
		if passes == "O2" {
			text = x86DwordProductIROptimize(t, ir)
		}
		for _, backend := range []string{"-O0", "-O2"} {
			t.Run("llvm-"+passes+backend, func(t *testing.T) {
				execution.compileAndRunLLVM(t, "streaming", text, c, backend)
			})
		}
	}
	// Preserve every streaming kernel above, then execute the distinct typed
	// MMX-to-GP consumer through its original Go and independent C oracles.
	t.Run("move-mask", x86NativeMMXMoveMaskRuntime)
}
