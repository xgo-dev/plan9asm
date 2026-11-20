package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalBlockTransfer(t *testing.T) {
	fixedLocalVectorRuntime(t, fixedLocalVEXNativeTools(t), true, fixedLocalBlockRuntimeKernels())
}
