package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalIntegerCompare(t *testing.T) {
	fixedLocalVectorRuntime(t, fixedLocalVEXNativeTools(t), true, fixedLocalIntegerCompareRuntimeKernels(t))
}
