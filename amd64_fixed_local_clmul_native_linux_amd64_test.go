package plan9asm

import "testing"

// Original Go executes every legacy and VEX kernel before comparison with
// the three LLVM APIs. Missing ISA or a failed preflight is a failure, not a
// skipped execution receipt or an object-only substitute.
func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalCLMUL(t *testing.T) {
	execution := fixedLocalVEXNativeTools(t)
	t.Logf("%s", execution.run(t, fixedLocalCLMULRuntimePreflight(t, execution)))
	fixedLocalVectorRuntime(t, execution, true, fixedLocalCLMULRuntimeKernels(t))
	x87IA32RequireNativeHost(t)
}
